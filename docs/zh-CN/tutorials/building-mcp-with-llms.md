# 实战指南：将 MCP 与大语言模型工具安全桥接至 iFay 协议栈

大语言模型（LLM）与模型上下文协议（MCP，Model Context Protocol）生态已经沉淀了丰富的工具服务（如日历检索、工单提交、智能家居控制等）。但在通用 Agent 架构中，直接将 MCP 工具暴露给大模型往往面临三大隐患：

1. **工具来源未验签**：难以密码学验证某个工具描述符究竟由哪个发布方签发、传输途中是否被篡改（投毒攻击）；
2. **交互副作用缺乏显式同意**：模型可能在纯文本对话流中静默触发不可逆副作用，缺乏结构化参数披露与人类原型确认；
3. **宿主（Host）权限边界模糊**：缺少与人类原型授权等级（`G0`–`G4`）及硬件安全态绑定的确定性门禁。

在 iFay 体系中，嵌入式的本地 **Ego** 模型并不排斥外部大模型或 MCP 工具，而是通过 **`SSP 1.0`（技能发现验签）→ `ICP 1.0`（结构化交互与同意）→ `CAP 1.0`（客户端控制权限门禁）** 三道协议防线，把不受信任的外部工具调用纳入可审计的人类原型主权边界内。

---

## 桥接架构总览

```text
[MCP 工具服务]
      │ 1. 导出工具 Schema 并签发 SSP 1.0 SkillDescriptor (JCS + Detached Ed25519 JWS)
      ▼
[iFay 注册技能层 (@ifay/sdk: verifySkillDescriptor)]
      │ 2. LLM 生成调用提案；若涉及高风险/不可逆操作，构造 ICP 1.0 .ctx 结构化确认卡片
      ▼
[人类原型 (Human Prime)] ── 核验披露参数并签发确认回执 (confirmed_params_sha256)
      │ 3. 连同 Faying Mandate 一起送入 CAP 1.0 门禁 (@ifay/sdk: evaluateCapAction)
      ▼
[宿主设备 / 应用执行层 (Host)]
```

---

## 第 1 步：将 MCP Tool 包装为经签名的 `SSP 1.0` 技能描述符

假设你有一个现有的 MCP 工具 `calendar.reschedule_meeting`。在接入 iFay 注册技能目录前，技能发布方使用自己的 `FayID` 密钥对，通过 `@ifay/sdk` 的 `signSkillDescriptor` 对描述符生成遵循 RFC 8785 JCS 与分离式 Ed25519 JWS（`alg: "EdDSA"`）的 `SkillProof`：

```javascript
import { randomBytes } from 'node:crypto';
import {
  deriveEntityKeypair,
  signSkillDescriptor,
  verifySkillDescriptor,
} from './packages/ifay-sdk/src/index.mjs';

// 技能提供方身份（ifay_ 或 org_）
const providerSeed = randomBytes(32);
const skillPublisher = deriveEntityKeypair(providerSeed, 'org', 'acme-mcp-bridge').value;

// 将 MCP Tool 定义映射为 SSP 1.0 SkillDescriptor
const mcpBridgedDescriptor = {
  protocol: 'ssp/1.0',
  version: '1.0',
  skillId: 'skill.mcp.calendar.reschedule',
  name: 'MCP Calendar Rescheduler',
  description: '调整日历会议时间并向参会人发送更新通知',
  publisherFayId: skillPublisher.entityId,
  origin: 'https://mcp-bridge.acme.example',
  visibility: 'restricted',
  executionMode: 'sync',
  inputSchema: {
    type: 'object',
    required: ['eventId', 'newStartIso', 'notifyAttendees'],
    properties: {
      eventId: { type: 'string' },
      newStartIso: { type: 'string' },
      notifyAttendees: { type: 'boolean' },
    },
  },
  outputSchema: {
    type: 'object',
    required: ['updated', 'updatedAtIso'],
  },
};

// 生成分离式 Ed25519 JWS 签名证明 (SkillProof)
const signedSkill = signSkillDescriptor(mcpBridgedDescriptor, {
  signer: skillPublisher,
  kid: `${skillPublisher.entityId}#ssp-1`,
  created: new Date().toISOString(),
});

// iFay 客户端在挂载该工具前进行密码学验签、版本兼容校验与受限可见性鉴权
const callerIfay = deriveEntityKeypair(randomBytes(32), 'ifay', 0).value;
const verifyResult = verifySkillDescriptor(signedSkill, {
  trustedPublicKeyHex: skillPublisher.publicKeyHex,
  consumerVersion: '1.0',
  requireAuthForRestricted: true,
  callerFayId: callerIfay.entityId,
});

console.log('SSP 技能验签结果 :', verifyResult);
// { valid: true, publisherFayId: 'org_...', kid: 'org_...#ssp-1' }
```

> **前向兼容提示**：遵循两段式 `MAJOR.MINOR` 规则，当未来服务端发布 `version: "1.1"` 的描述符并附带新的可选元数据时，`1.0` 客户端的 `verifySkillDescriptor` 会保留未知可选字段参与 JCS 验签并正常放行，同时严格拒绝 `2.0` 等跨主版本描述符。

---

## 第 2 步：使用 `ICP 1.0` `.ctx` 结构化交互块获取人类原型显式同意

当大语言模型推理出“需要将会议 `evt_9042` 改期并通知外部参会人”时，由于向外部联系人群发改期通知具有**不可撤回的外部后果（`irreversible_consequence`）**，iFay 不应仅凭 LLM 的自由文本输出直接放行。

按照 **交互内容协议（`ICP 1.0`）** 的设计理念，客户端向人类原型渲染结构化 `.ctx` 交互块，清晰披露即将执行的工具名称、规范化参数摘要与风险等级，只有人类原型显式点击确认动作后，才产出与参数哈希绑定的确认回执：

```javascript
import { computeCapParamsSha256 } from './packages/ifay-sdk/src/index.mjs';

// 大模型产出的结构化工具调用参数
const proposedToolParams = {
  eventId: 'evt_9042',
  newStartIso: '2026-11-18T14:00:00Z',
  notifyAttendees: true,
};

// 计算与参数字节精确绑定的 RFC 8785 JCS SHA-256 摘要
const paramsSha256 = computeCapParamsSha256(proposedToolParams);

// 构造面向人类原型的 ICP .ctx 结构化确认载荷（示意）
const icpConsentBlock = {
  protocol: 'icp/1.0',
  blockType: 'application/vnd.ifay.ctx+json',
  cardId: 'ctx_confirm_reschedule_01',
  title: '确认执行会议改期并发送通知',
  disclosure: {
    skillId: signedSkill.skillId,
    publisher: signedSkill.publisherFayId,
    irreversibility: 'irreversible_consequence',
    parameters: proposedToolParams,
    paramsSha256,
  },
  reactions: [
    { id: 'approve_once', label: '确认执行（单次有效）', requiresExplicitConsent: true },
    { id: 'cancel', label: '取消', requiresExplicitConsent: false },
  ],
};

console.log('待展示 ICP .ctx 参数绑定摘要 :', icpConsentBlock.disclosure.paramsSha256);
```

如果大模型在后续轮次中试图偷偷篡改 `proposedToolParams`（例如将 `notifyAttendees` 或收件人范围扩大），其重新计算的 JCS 哈希将与人类原型确认时的 `confirmed_params_sha256` 不一致，在下一步被 `CAP 1.0` 门禁立即拦截。

---

## 第 3 步：通过 `CAP 1.0` 门禁守护本地与桥接工具的最终执行

在真正调用底层 MCP 执行器或宿主驱动之前，使用 `evaluateCapAction` 执行 `D-1..D-7` 全量安全检查：

1. **不可降级地板（`D-6`）**：即便上层 LLM 编排器试图传入 `caller_criticality_override: 'routine'`，只要清单将该动作标注为 `irreversible_consequence`，评估器都会强制将其有效风险等级抬升至至少 `high`（`escalation_clamped: true`）；
2. **参数绑定人工确认（`D-7`）**：`high` 级不可逆操作必须附带未过期、经过终端披露见证且 `confirmed_params_sha256` 完全匹配的人类原型确认记录；
3. **金融转账越界阻断（`D-7c`）**：任何标记为 `domain_category: 'fund_transfer'` 的动作在 `CAP 1.0` 中均被无条件拒绝（`2007 E_OUT_OF_SCOPE_FUND_TRANSFER`），防止通用 LLM 工具越权触碰资金划转。

```javascript
import {
  createFayingMandate,
  toCapMandateBinding,
  ed25519KeypairFromSeed,
  signCapDriverManifest,
  evaluateCapAction,
} from './packages/ifay-sdk/src/index.mjs';

const hpSeed = randomBytes(32);
const humanPrime = deriveEntityKeypair(hpSeed, 'hid', 0).value;
const nowMs = Date.now();

// 宿主桥接器能力清单：将外部通知动作声明为 irreversible_consequence
const bridgeAnchorSeed = randomBytes(32);
const bridgeAnchorKey = ed25519KeypairFromSeed(bridgeAnchorSeed);
const trustAnchors = {
  mcp_bridge_anchor: {
    algorithm: 'Ed25519',
    public_key_raw_hex: bridgeAnchorKey.publicKeyHex,
  },
};

const bridgeCapabilityManifest = signCapDriverManifest(
  {
    manifest_id: 'mf_mcp_calendar_bridge',
    driver_id: 'drv_mcp_calendar',
    version: '1.0.0',
    issued_at: new Date(nowMs).toISOString(),
    signer_key_id: 'mcp_bridge_anchor',
    resources: [
      {
        resource_id: 'res_mcp_calendar',
        safe_states: [{ safe_state_id: 'disconnect_mcp_transport', description: '断开外部 MCP 会话' }],
        operations: [
          {
            operation_id: 'reschedule_meeting',
            mode: 'execute',
            criticality: 'sensitive',
            consequence_irreversibility: 'irreversible_consequence',
            domain_category: 'external_communication',
          },
        ],
      },
    ],
  },
  bridgeAnchorSeed,
);

const mandate = createFayingMandate(
  {
    mandateId: 'mnd_mcp_01',
    humanPrimeId: humanPrime.entityId,
    fayId: callerIfay.entityId,
    grade: 'G2',
    scope: {
      resources: ['res_mcp_calendar'],
      actions: ['execute'],
      domains: ['https://mcp-bridge.acme.example'],
      terminals: ['host:desktop:primary'],
    },
    deviceId: 'host:desktop:primary',
    issuedAtEpochMs: nowMs,
    expiresAtEpochMs: nowMs + 5 * 60 * 1000,
  },
  humanPrime,
);

// 附带来自第 2 步 ICP .ctx 卡片的人类原型参数绑定确认
const gateDecision = evaluateCapAction(
  {
    protocol_version: '1.0',
    request_id: 'req_mcp_exec_01',
    fay_id: callerIfay.entityId,
    now_epoch_ms: nowMs + 1000,
    resource_id: 'res_mcp_calendar',
    operation_id: 'reschedule_meeting',
    requested_mode: 'execute',
    caller_criticality_override: 'routine', // LLM 试图降级风险，将被自动钳制回 high
    params: proposedToolParams,
    manifest: bridgeCapabilityManifest,
    grant: {
      grant_id: 'grt_mcp_01',
      resource_id: 'res_mcp_calendar',
      allowed_modes: ['execute'],
      min_grade: 'G2',
      mandate_binding: toCapMandateBinding(mandate, 'res_mcp_calendar'),
    },
    human_confirmation: {
      confirmation_id: 'cnf_ctx_01',
      human_prime_id: humanPrime.entityId,
      confirmed_params_sha256: paramsSha256,
      terminal_attested_disclosure: true,
      expires_at_epoch_ms: nowMs + 60 * 1000,
    },
  },
  trustAnchors,
);

console.log('CAP 门禁最终判定 :', gateDecision);
// { decision: 'ALLOW', effective_criticality: 'high', effective_grade: 'G2', escalation_clamped: true }
```

只有在 `gateDecision.decision === 'ALLOW'` 时，你的 MCP 桥接适配器才真正向底层 MCP Server 发出 `tools/call` JSON-RPC 请求。

---

## 安全核对清单（Checklist）

在将自定义 MCP Server 或第三方大模型工具投入生产前，请逐项核验：

- [ ] **全部工具均附带 `SSP 1.0` `SkillProof`**：拒绝加载未签名、JWS 验签失败或主版本号不兼容的工具描述符；
- [ ] **未声明操作默认拒绝**：桥接层能力清单只列出经过审计的 MCP 工具名，任何模型幻觉出的未知工具名在 `CAP 1.0` 中自动归为 `critical` 并拒绝；
- [ ] **不可逆外部动作接入 `ICP 1.0` 显式同意**：发送邮件/消息、删除数据、修改外部日程等操作必须经过结构化披露并校验 `confirmed_params_sha256`；
- [ ] **随时响应 `G0` 紧急接管**：一旦人类原型发出 `G0` 抢占信号，桥接器立即中断在途工具调用并切入 `safe_state_id` 定义的安全状态。

---

## 延伸阅读

- [实战教程：15 分钟构建并验证本地 iFay 客户端节点](./building-a-client-node.md)
- [蓝图 09：交互层 - 感知（含交互内容协议 ICP）](../blueprint/09-交互层-感知.md)
- [蓝图 10：交互层 - 动作（含控制权限协议 CAP）](../blueprint/10-交互层-动作.md)
- [蓝图 12：认知层 - 技能（含技能共享协议 SSP）](../blueprint/12-认知层-技能.md)
- [在线文档入口（中文）](https://ifay.ai/zh-CN/docs/iFay/tutorials/building-mcp-with-llms)
