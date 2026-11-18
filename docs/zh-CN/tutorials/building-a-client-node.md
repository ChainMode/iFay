# 实战教程：15 分钟使用 `@ifay/sdk` 与 `@ifay/ifacts` 构建并验证本地 iFay 客户端节点

本教程面向首次接入 iFay 体系的开发者与宿主（Host）工程师。在 15 分钟内，你将零依赖地使用主仓库内置的官方开发套件 `@ifay/sdk` 与合规验证套件 `@ifay/ifacts`，完成一个**第二阶段（直接接管客户端）** iFay 节点的身份派生、声明式组装、人类原型授权签发、`CAP 1.0` 安全门禁校验、端到端加密传输以及 **iFay Ready** 合规自检。

---

## 环境前提

- **Node.js `>= 20.0.0`**（仅使用内置 `node:crypto`、`node:fs` 与 `node:test`，无需执行 `npm install` 联网下载任何第三方运行时包）。
- 克隆 `ifay` 主仓库并进入工作目录：

```bash
git clone https://github.com/ChainMode/iFay.git
cd iFay
```

---

## 第 1 步：先运行一键合规自检（2 分钟）

在编写代码前，先运行内置的 `ifacts` CLI 验证本地环境与测试基线是否就绪：

```bash
node packages/ifacts-harness/bin/ifacts.mjs --self-test
```

你将看到如下分级摘要输出（渐进式门禁按 `L1 → L2 → L3` 顺序逐级放行）：

```text
[iFACTS] Report Format : ifacts-report/1.0
[iFACTS] Subject       : ifay_3atyjm7qw4dbchkbec5hy22t4pope5qc55aozxhrm722c6tlsf6q
[iFACTS] Resolved Phase: Phase 2
[iFACTS] L1 Status     : passed (6/6)
[iFACTS] L2 Status     : passed (4/4)
[iFACTS] L3 Status     : passed (7/7)
[iFACTS] L4 Status     : deferred_phase_4_behavioral
[iFACTS] iFay Ready    : Gold
[iFACTS] Overall       : PASSED
```

---

## 第 2 步：派生人类原型与 iFay 规范身份（3 分钟）

iFay 要求每一个体化身（`ifay_`）都受控于明确的**人类原型**（Human Prime，`hid_`）。二者均遵循 RFC 4648 小写无填充 Base32 规范格式，并通过 HKDF-SHA256 域分离从主种子确定性派生 Ed25519 持有者证明（Holder-of-Key）密钥对。

在本地新建一个演练脚本（例如 `/tmp/quickstart-client.mjs`，或放在你自己的项目目录中并指向 `packages/ifay-sdk/src/index.mjs`）：

```javascript
import { randomBytes } from 'node:crypto';
import {
  deriveEntityKeypair,
  createFayManifest,
  validateFayManifest,
  resolveFayManifestDependencies,
  classifyFayManifestPhase,
  createFayingMandate,
  verifyFayingMandate,
  toCapMandateBinding,
  ed25519KeypairFromSeed,
  signCapDriverManifest,
  evaluateCapAction,
  encodeDtpFrame,
  decodeDtpFrame,
} from './packages/ifay-sdk/src/index.mjs';
import { runIfactsSuite } from './packages/ifacts-harness/src/index.mjs';

// 1. 生成本地演练用的 32 字节主种子（生产环境中请存放在操作系统安全密钥链或硬件安全模块中）
const masterSeed = randomBytes(32);

// 2. 分别派生人类原型（hid_）与个体化身（ifay_）密钥对
const humanPrime = deriveEntityKeypair(masterSeed, 'hid', 0).value;
const myIfay = deriveEntityKeypair(masterSeed, 'ifay', 0).value;

console.log('人类原型 ID :', humanPrime.entityId);
console.log('iFay ID    :', myIfay.entityId);
```

---

## 第 3 步：声明式组装 `FayManifest` 并解析阶段依赖（3 分钟）

借助 `createFayManifest`，你只需声明业务所需的模块与协议（例如接管智能桌面宿主所需的 `device_driver_hub`、`sensor` 以及 `cap_protocol`、`dtp_protocol`），系统会自动推理其所属演进阶段并补全 7 项核心基础设施模块：

```javascript
const manifest = createFayManifest({
  name: 'workstation-companion-node',
  version: '0.1.0',
  description: '面向桌面宿主设备的本地 iFay 客户端节点',
  vendor: 'Example Lab',
  fayId: myIfay.entityId,
  controlMode: 'ego',
  modules: ['device_driver_hub', 'sensor'],
  protocols: ['cap_protocol', 'dtp_protocol'],
  drivers: [
    {
      name: 'DesktopTelemetryDriver',
      type: 'workstation',
      driverPackage: '@ifay-drivers/desktop-telemetry',
    },
  ],
  ego: {
    modelSource: '@ifay-ego/workstation-base',
    scenarioTags: ['desktop', 'offline-control'],
  },
});

const validation = validateFayManifest(manifest);
const resolvedDeps = resolveFayManifestDependencies(manifest);
const phaseInfo = classifyFayManifestPhase(manifest);

console.log('清单校验通过 :', validation.valid);
console.log('识别演进阶段 :', phaseInfo.phase); // Phase 2
console.log('自动补全基础设施 :', resolvedDeps.autoCompletedModules);
```

---

## 第 4 步：签发 `Faying 1.0` 授权并执行 `CAP 1.0` 安全门禁（4 分钟）

任何 iFay 都不能在缺乏人类原型明确意图的情况下擅自驱动宿主（Host）硬件。下面演示：
1. 由人类原型向 `myIfay` 签发一份限定资源范围与有效期的 `G2` 级授权信封（Mandate）；
2. 验证已签名的宿主驱动能力清单（`DriverCapabilityManifest`）；
3. 通过 `evaluateCapAction` 执行 `CAP 1.0` 客户端安全评估（验证合法 `read` 放行、未声明动作默认升至 `critical` 并拒绝，以及 `G0` 紧急接管触发安全态指令且绝不阻塞人类原型接管）：

```javascript
const nowMs = Date.now();

// 1. 人类原型签发 G2 级授权信封
const mandate = createFayingMandate(
  {
    mandateId: 'mnd_workstation_001',
    humanPrimeId: humanPrime.entityId,
    fayId: myIfay.entityId,
    grade: 'G2',
    scope: {
      resources: ['res_workstation_sensor'],
      actions: ['read'],
      domains: ['local://workstation'],
      terminals: ['host:desktop:primary'],
    },
    deviceId: 'host:desktop:primary',
    issuedAtEpochMs: nowMs,
    expiresAtEpochMs: nowMs + 10 * 60 * 1000,
  },
  humanPrime,
);

const mandateCheck = verifyFayingMandate(mandate, {
  trustedIssuerPublicKeyHex: humanPrime.publicKeyHex,
  nowEpochMs: nowMs + 1000,
  requiredResource: 'res_workstation_sensor',
  requiredAction: 'read',
});
console.log('Faying Mandate 校验 :', mandateCheck);

// 2. 构造并签名宿主驱动能力清单
const driverVendorSeed = randomBytes(32);
const driverVendorKey = ed25519KeypairFromSeed(driverVendorSeed);
const trustAnchors = {
  vendor_key_01: {
    algorithm: 'Ed25519',
    public_key_raw_hex: driverVendorKey.publicKeyHex,
  },
};

const driverManifest = signCapDriverManifest(
  {
    manifest_id: 'mf_desktop_01',
    driver_id: 'drv_desktop_telemetry',
    version: '1.0.0',
    issued_at: new Date(nowMs).toISOString(),
    signer_key_id: 'vendor_key_01',
    resources: [
      {
        resource_id: 'res_workstation_sensor',
        safe_states: [{ safe_state_id: 'standby_readonly', description: '切回只读待机安全态' }],
        operations: [
          {
            operation_id: 'read_cpu_thermals',
            mode: 'read',
            criticality: 'routine',
            consequence_irreversibility: 'reversible',
            domain_category: 'device_control',
          },
        ],
      },
    ],
  },
  driverVendorSeed,
);

// 3. 评估常规读取请求 -> ALLOW
const allowDecision = evaluateCapAction(
  {
    protocol_version: '1.0',
    request_id: 'req_01',
    fay_id: myIfay.entityId,
    now_epoch_ms: nowMs + 1000,
    resource_id: 'res_workstation_sensor',
    operation_id: 'read_cpu_thermals',
    requested_mode: 'read',
    params: {},
    manifest: driverManifest,
    grant: {
      grant_id: 'grt_01',
      resource_id: 'res_workstation_sensor',
      allowed_modes: ['read'],
      min_grade: 'G2',
      mandate_binding: toCapMandateBinding(mandate, 'res_workstation_sensor'),
    },
  },
  trustAnchors,
);
console.log('CAP 常规读取判定 :', allowDecision.decision); // ALLOW

// 4. 模拟人类原型触发 G0 紧急接管 -> 立即拒绝自动化指令并输出安全态切换指令
const g0Decision = evaluateCapAction(
  {
    protocol_version: '1.0',
    request_id: 'req_02_g0',
    fay_id: myIfay.entityId,
    now_epoch_ms: nowMs + 2000,
    resource_id: 'res_workstation_sensor',
    operation_id: 'read_cpu_thermals',
    requested_mode: 'read',
    g0_override: true,
    params: {},
    manifest: driverManifest,
    grant: {
      grant_id: 'grt_01',
      resource_id: 'res_workstation_sensor',
      allowed_modes: ['read'],
      min_grade: 'G2',
      mandate_binding: toCapMandateBinding(mandate, 'res_workstation_sensor'),
    },
  },
  trustAnchors,
);
console.log('G0 紧急抢占判定 :', g0Decision.decision, g0Decision.safe_state_directive);
```

---

## 第 5 步：封装 `DTP 1.0` 加密数据帧并运行 `iFACTS` 认证（3 分钟）

当宿主需要将采集到的结构化传感器数据回传给 iFay 持久监护时，使用 `DTP 1.0`（RFC 8785 JCS 帧头 + AES-256-GCM 认证加密载荷）封装传输，最后调用 `runIfactsSuite` 对整个清单执行 L1–L3 渐进式合规认证：

```javascript
// 1. DTP 1.0 帧加密与解包
const sessionKey = randomBytes(32);
const iv = randomBytes(12);
const frame = encodeDtpFrame(
  {
    version: '1.0',
    channelId: 'ch_thermals_01',
    direction: 'terminal_to_ifay',
    sequence: 1,
    contentType: 'application/json',
  },
  Buffer.from(JSON.stringify({ cpuTempCelsius: 52.4 }), 'utf8'),
  sessionKey,
  iv,
);
const decoded = decodeDtpFrame(frame.wireFrame, sessionKey);
console.log('DTP 解密载荷 :', decoded.ok ? decoded.plaintext.toString('utf8') : decoded.errorName);

// 2. 运行 iFACTS L1 -> L2 -> L3 合规套件并评估 Silver 级宿主就绪度
const report = runIfactsSuite({
  manifest,
  appCapabilities: {
    capProtocol: true,
    dtpProtocol: true,
    credentialDelegation: true,
  },
});

console.log('iFACTS 总体结论 :', report.overallStatus); // passed
console.log('iFay Ready 等级 :', report.ifayReady.tier); // Silver
```

你也可以直接将构造好的 `manifest` 保存为 JSON 文件，通过命令行工具输出完整的机器可读 `ifacts-report/1.0` 报告：

```bash
node packages/ifacts-harness/bin/ifacts.mjs \
  --manifest schema/faymanifest/examples/drone-controller.faymanifest.json \
  --json
```

> **注意（`iFay` 与 `coFay` 的合规边界）**：`iFACTS` 仅验证个体化身（`ifay_`）。若传入 `cofay_` 主体标识，`ifacts` 将明确拒绝并返回错误码 `COFAY_OUT_OF_SCOPE_USE_COFACTS`（退出码 `2`）——集体化身的治理验证属于独立的 `coFACTS` 体系。

---

## 下一步

- 继续阅读[《实战指南：将 MCP 与大语言模型工具安全桥接至 iFay 协议栈》](./building-mcp-with-llms.md)，学习如何为外部 LLM/MCP 工具签发 `SSP 1.0` 技能证明并结合 `ICP 1.0` 与 `CAP 1.0` 构建纵深安全防线。
- 查阅 [`packages/ifay-sdk/README.md`](../../../packages/ifay-sdk/README.md) 与 [`packages/ifacts-harness/README.md`](../../../packages/ifacts-harness/README.md) 获取完整 API 参考。
- [在线文档入口（中文）](https://ifay.ai/zh-CN/docs/iFay/tutorials/building-a-client-node)
