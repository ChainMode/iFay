## Summary

<!-- Briefly describe what this PR changes and why. -->

## Affected Workspace / Area

- [ ] `@ifay/sdk` (`packages/ifay-sdk`)
- [ ] `@ifay/ifacts` (`packages/ifacts-harness`)
- [ ] `@ifay/mcp-server` (`packages/mcp-server`)
- [ ] `FayManifest` schema / fixtures (`schema/faymanifest`)
- [ ] Documentation (`README.md`, `PUBLISHING.md`, `docs/`)

## Verification Checklist

- [ ] `npm run build && npm test && npm run demo` pass on Node.js `>= 20`
- [ ] `npm pack --dry-run --workspaces` succeeds cleanly
- [ ] Relative links and canonical terminology (`Human Prime`, `Host` strictly for devices/apps, `iFay`, `coFay`, `GMChain`, `MeriToken`) pass `docs-ci.yml`
- [ ] Commits include a DCO 1.1 `Signed-off-by:` trailer (`git commit -s`) per [`CONTRIBUTING.md`](../CONTRIBUTING.md)
