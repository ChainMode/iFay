# `@ifay/mcp-server`

Zero-dependency **Model Context Protocol (MCP)** stdio server (`2024-11-05` & `2025-03-26` compatible) exposing cryptographic validation and Host/tool safety gating for **iFay** agents.

Built strictly on `@ifay/sdk` and Node.js `>= 20` built-in `node:crypto` (Ed25519, SHA-256, HKDF-SHA256, RFC 8785 JCS) with **zero third-party runtime dependencies**.

## Exposed MCP Tools

| Tool | Purpose |
|------|---------|
| `fayid_validate` | Validate canonical `ifay_`, `hid_`, `cofay_`, `org_`, `dyn_`, `grt_`, `vrf_`, and `gmcref_` identifiers, optional `did:fay:...` consistency, Ed25519 public-key SHA-256 hash binding, and Holder-of-Key challenge signatures. |
| `faymanifest_validate` | Validate a `FayManifest` JSON payload against the authoritative [`faymanifest.schema.json`](../../schema/faymanifest/faymanifest.schema.json) and return auto-completed infrastructure modules, governed package namespaces, and `Phase 1`–`Phase 5` classification. |
| `cap_evaluate` | Evaluate an AI agent Host or tool action against a signed `Control Authority Protocol` (`CAP 1.0`) `DriverCapabilityManifest` and `Faying 1.0` Mandate from a Human Prime. Returns deterministic `ALLOW` / `DENY`, explicit `D-1..D-7` rule IDs, `G0` safe-state directives, and a SHA-256 `auditTrace`. |
| `ssp_verify_descriptor` | Validate a `Skill Sharing Protocol` (`SSP 1.0`) skill descriptor and verify optional RFC 8785 JCS + Detached Ed25519 JWS (`alg: "EdDSA"`) `SkillProof` signatures. |

## Connecting MCP Hosts (Claude Desktop / Cursor / Windsurf)

From a local clone (after `npm install`):

```json
{
  "mcpServers": {
    "ifay": {
      "command": "node",
      "args": ["/absolute/path/to/iFay/packages/mcp-server/dist/cli.js"]
    }
  }
}
```

Or once published to npm:

```json
{
  "mcpServers": {
    "ifay": {
      "command": "npx",
      "args": ["-y", "@ifay/mcp-server"]
    }
  }
}
```

## Running Tests

```bash
npm run build --workspace=@ifay/mcp-server
npm test --workspace=@ifay/mcp-server
```

## License

MIT — see [LICENSE](../../LICENSE).
