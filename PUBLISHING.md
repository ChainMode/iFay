# Publishing `@ifay/*` Workspace Packages

This umbrella repository manages four public npm packages under `packages/`:

| Package | Path | CLI Binary | Runtime Dependencies |
|---------|------|------------|----------------------|
| [`@ifay/sdk`](./packages/ifay-sdk/README.md) | `packages/ifay-sdk` | `ifay-demo` | Zero external dependencies (`node:*` built-ins only) |
| [`@ifay/soul`](./packages/ifay-soul/README.md) | `packages/ifay-soul` | `ifay-soul` | `@ifay/sdk` + `node:*` built-ins |
| [`@ifay/ifacts`](./packages/ifacts-harness/README.md) | `packages/ifacts-harness` | `ifacts` | Zero external dependencies (`node:*` built-ins only) |
| [`@ifay/mcp-server`](./packages/mcp-server/README.md) | `packages/mcp-server` | `ifay-mcp-server` | `@ifay/sdk` + `node:*` built-ins |

---

## 1. Prerequisites

- **Node.js `>= 20.0.0`** and **npm `>= 10`**
- Clean Git working tree on `main` (`git status` shows no uncommitted changes)
- Authenticated npm account with publish rights to the `@ifay` scope (`npm whoami`)

---

## 2. Clean Build & Verification

Run the full build, unit/integration suite, interactive cryptographic walkthrough, and progressive iFACTS self-test from the repository root:

```bash
npm ci
npm run build
npm test
npm run demo
npm run ifacts:self-test
```

---

## 3. Inspect Package Tarballs (`--dry-run`)

Before publishing, verify exact tarball contents and `files` allowlists across all four workspace packages:

```bash
npm pack --dry-run --workspaces
```

Confirm that:
- `@ifay/sdk` includes `src/`, `dist/cli.js`, `dist/faymanifest.schema.json`, `README.md`, and `package.json`.
- `@ifay/soul` includes `src/`, `bin/ifay-soul.mjs`, `README.md`, and `package.json`.
- `@ifay/ifacts` includes `src/`, `bin/ifacts.mjs`, `README.md`, and `package.json`.
- `@ifay/mcp-server` includes `dist/index.js`, `dist/index.d.ts`, `dist/cli.js`, `server.json`, `README.md`, and `package.json`.
- No internal governance or test files are bundled into the tarballs.

---

## 4. Publish to npm

Because `@ifay/mcp-server` depends on `@ifay/sdk`, npm workspaces publishes in workspace order (`packages/ifay-sdk` → `packages/ifacts-harness` → `packages/mcp-server`):

```bash
npm publish --workspaces --access public
```

To publish a single workspace package individually:

```bash
npm publish --workspace=@ifay/sdk --access public
npm publish --workspace=@ifay/ifacts --access public
npm publish --workspace=@ifay/mcp-server --access public
```

---

## 5. Licensing Note

All published workspace packages (`packages/*`) and JSON Schemas (`schema/*`) are distributed under the **MIT License** ([LICENSE](./LICENSE)). Narrative specifications and blueprints under `docs/` remain licensed under **CC BY 4.0** ([LICENSE-DOCS](./LICENSE-DOCS)).
