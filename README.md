# iFay

![](https://github.com/user-attachments/assets/2cd8f495-58a3-4085-a38b-164d2edfc586)


iFay (Individual Fay) is an AI avatar that integrates a Human Prime's personality traits and digital capabilities.

<br>

### Official SDK & Conformance Suite

This umbrella repository hosts the authoritative `FayManifest` schema alongside the zero-dependency reference SDK and progressive conformance harness (requires **Node.js `>= 20.0.0`**):

| Package / Directory | Description |
|---------------------|-------------|
| [`packages/ifay-sdk`](./packages/ifay-sdk/README.md) (`@ifay/sdk`) | Official zero-dependency SDK for `FayID` (RFC 4648 lowercase no-pad Base32 + HKDF-SHA256 subkeys + Ed25519 Holder-of-Key + RFC 8785 JCS), `Faying 1.0` Mandate envelopes, `FayManifest` builder/validator, `CAP 1.0` `D-1..D-7` client safety gate, `SSP 1.0` Detached Ed25519 JWS `SkillProof`, `DTP 1.0` AES-256-GCM frames, and `Ego` two-tier Vault verification |
| [`packages/ifacts-harness`](./packages/ifacts-harness/README.md) (`@ifay/ifacts`) | Runnable **iFACTS** conformance suite enforcing the progressive `L1 → L2 → L3` gate (`blocked_by_previous_level`), explicit `coFay` / `coFACTS` scope separation, SHA-256 hash-chained E2E lifecycle verification, `iFay Ready` (`None` / `Bronze` / `Silver` / `Gold`) certification, and `ifacts-report/1.0` output |
| [`schema/faymanifest`](./schema/faymanifest/) | Authoritative JSON Schema (`faymanifest.schema.json`) and validated reference fixtures for declarative iFay assembly |

```bash
# Run all unit/integration tests (@ifay/sdk + @ifay/ifacts + FayManifest fixtures)
npm test

# Run the progressive L1 -> L2 -> L3 iFACTS conformance self-test
node packages/ifacts-harness/bin/ifacts.mjs --self-test
```

#### Quickstart & Engineering Documentation
- **Tutorials**:
  - [Build and Verify a Local iFay Client Node in 15 Minutes](./docs/en/tutorials/building-a-client-node.md) ([中文](./docs/zh-CN/tutorials/building-a-client-node.md))
  - [Bridging MCP and LLM Tools Safely into the iFay Protocol Stack](./docs/en/tutorials/building-mcp-with-llms.md) ([中文](./docs/zh-CN/tutorials/building-mcp-with-llms.md))
- **Roadmap & Specification Governance**:
  - [Ecosystem Roadmap and Engineering Milestones](./docs/en/development/roadmap.md) ([中文](./docs/zh-CN/development/roadmap.md))
  - [Versioning and Edition Freeze Discipline (`MAJOR.MINOR`)](./docs/en/specification/versioning.md) ([中文](./docs/zh-CN/specification/versioning.md))

<br>

### Getting Started
- #### Overview

  - [Our Vision](https://github.com/ChainModePilot/iFay/wiki#our-vision)
  - [Foresee the Future](https://github.com/ChainModePilot/iFay/wiki#-foresee-the-future)
  - [Vocabulary: Definition & Concept](https://github.com/ChainModePilot/iFay/wiki/Definition-and-Concept)
  - [Why is "Fay"](https://github.com/ChainModePilot/iFay/wiki#%EF%B8%8F-why-do-i-use-fay-instead-of-agent-as-the-name)
  - [Framework of iFay](https://github.com/ChainModePilot/iFay/wiki#-framework-of-ifay)
  - [Roadmap: 5 steps](https://github.com/ChainModePilot/iFay/wiki/Roadmap:-5-steps)
    - [Phase 1：Simulate Human Operations](https://github.com/ChainModePilot/iFay/wiki/Roadmap:-5-steps)
    - [Phase 2：Direct Takeover Client](https://github.com/ChainModePilot/iFay/wiki/Roadmap:-5-steps#2%EF%B8%8F%E2%83%A3-phase-ii-direct-takeover-client)
    - [Phase 3：iFay Serves As The Interface With Virtual World](https://github.com/ChainModePilot/iFay/wiki/Roadmap:-5-steps#3%EF%B8%8F%E2%83%A3-phase-iii-ifay-serves-as-the-interface-with-virtual-world)
    - [Phase 4：iFay + coFay - Comprehensive Personification of Software](https://github.com/ChainModePilot/iFay/wiki/Roadmap:-5-steps#4%EF%B8%8F%E2%83%A3-phase-iv-ifay--cofay---comprehensive-personification-of-software)
    - [Phase 5：Fays Transforms The Labor Structure And Value Distribution Model](https://github.com/ChainModePilot/iFay/wiki/Roadmap:-5-steps#5%EF%B8%8F%E2%83%A3-phase-v-fays-transforms-the-labor-structure-and-value-distribution-model)

- #### iFay Entity

  - Social Layer
    - [Credentials Management](https://github.com/ChainModePilot/iFay/wiki/Credentials-Management)
  - Interaction Layer
    - Sense Organ
      - [First-person Tracer](https://github.com/ChainModePilot/iFay/wiki/First%E2%80%90person-Tracer)
      - [Sensor](https://github.com/ChainModePilot/iFay/wiki/Sensor)
      - [Self-awareness](https://github.com/ChainModePilot/iFay/wiki/Self%E2%80%90awareness)
    - Action Organ
      - [Simulated Operation](https://github.com/ChainModePilot/iFay/wiki/Simulated-Operation)
      - [Invoke Skill](https://github.com/ChainModePilot/iFay/wiki/Invoke-Skill)
      - [Self-driven Behavior](https://github.com/ChainModePilot/iFay/wiki/Self%E2%80%90driven-Behavior)
  - Cognition Layer
    - Thought Region
      - [Personal Data Heap](https://github.com/ChainModePilot/iFay/wiki/Personal-Data-Heap)
      - [External Knowledge](https://github.com/ChainModePilot/iFay/wiki/External-Knowledge)
      - [Aligned Consciousness](https://github.com/ChainModePilot/iFay/wiki/Aligned-Consciousness)
    - Skill Region
      - [Device Driver Hub](https://github.com/ChainModePilot/iFay/wiki/Device-Driver-Hub)
      - [Registered Skill](https://github.com/ChainModePilot/iFay/wiki/Registered-Skill)
      - [Internal Skill](https://github.com/ChainModePilot/iFay/wiki/Internal-Skill)
  - Ego Layer
    - [Ego Mini Model](https://github.com/ChainModePilot/Ego/wiki)

- #### Developer Guide
  - Open source project Developer
    - Data Model
    - FayGer( Virtual Runtime Environment )
      - Cross-language build tool
      - Cross-platform runtime container
    - Protocols
      - [Faying Protocol](https://github.com/ChainModePilot/Faying-Protocol/wiki)
      - [Interactive Conversation Protocol](https://github.com/ChainModePilot/Interactive-Conversation-Protocol/wiki)
      - [Telepathy Protocol](https://github.com/ChainModePilot/Telepathy-Protocol/wiki)
      - [Control Authority Protocol](https://github.com/ChainModePilot/Control-Authority-Protocol/wiki)
      - [Data Tunnel Protocol](https://github.com/ChainModePilot/Data-Tunnel-Protocol/wiki)
      - [Skill Sharing Protocol](https://github.com/ChainModePilot/Skill-Sharing-Protocol/wiki)
  - Application Developer
    - APP support Fayling with iFay
    - Hardware Device support Fayling with iFay
    - Cloud deploy FayGer runtime environments
    - Share Skills with iFay
    - Modular Multimodal Messages
  - Service Provider Developers
    - Develop and build iFay Entities


- #### [iFay Application](https://github.com/ChainModePilot/iFay/wiki/iFay-Application-Scenarios)
  - Obtain your own iFay
  - Faying: Connect with iFay
  - Interact with iFay
  - Use iFay to operate UI
    - Configure iFay’s attention
    - Teach iFay interface operations using natural language
    - Let iFay act autonomously
  - Take over client
    - Control hardware devices
    - Control software

<br>

### Contributing
We welcome contributions in all forms!
Whether you’re fixing bugs, improving documentation, or suggesting new features, please refer to our [Contribution Guide](./CONTRIBUTING.md), [Security Policy](./SECURITY.md), and [Code of Conduct](./CODE_OF_CONDUCT.md) to get started.

<br>

### 🎯 Vision

🔆 iFay will undertake the following **social values**:
1. Take over the mechanical, repetitive, dangerous labor and tedious auxiliary work of the Human Prime.
2. Improve the Human Prime's safety guarantee, health and quality of life.
3. Amplify the Human Prime's social value and obtain corresponding returns.

<br>

✅ iFay must follow the following **basic principles**:
1. Comply with social ethics and public order.
2. Align highly with the Human Prime (values, preferences, skills, permissions, power, responsibilities, habits, style), subject to Article 1.
3. Under Articles 1 and 2, control/take over/possess hardware/software, act autonomously, and always protect the Human Prime's rights.
4. Communicate efficiently with humans (including the Human Prime) and minimize ineffective interactions.
5. iFay can communicate via the Telepathy Protocol for higher efficiency and accuracy.

<br>

## License

This repository uses a dual-track open-source license (`Copyright (c) 2025-2026 ChainMode contributors`):

- **Code, Schemas, Fixtures & Workspace Packages** (`packages/`, `schema/`, `releases/`): Licensed under the **MIT License** — see [LICENSE](./LICENSE).
- **Specifications, Blueprints & Tutorials** (`docs/`): Licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)** — see [LICENSE-DOCS](./LICENSE-DOCS).


