# Contributing to iFay

Thank you for your interest in contributing to **iFay**! All participants are expected to uphold our [Code of Conduct](./CODE_OF_CONDUCT.md). For security-sensitive issues, please follow [SECURITY.md](./SECURITY.md) rather than opening a public issue or pull request.

## Local Setup & Verification

`iFay` requires **Node.js `>= 20.0.0`** and uses zero external runtime dependencies across `@ifay/sdk` and `@ifay/ifacts`.

```bash
# Clone your fork
git clone https://github.com/ChainMode/iFay.git
cd iFay

# Run the full workspace test suite (@ifay/sdk + @ifay/ifacts + FayManifest fixtures)
npm test

# Run individual package test suites directly with Node's built-in test runner
(cd packages/ifay-sdk && node --test tests/ifay-sdk.test.mjs)
(cd packages/ifacts-harness && node --test tests/ifacts-harness.test.mjs)

# Run the progressive L1 -> L2 -> L3 iFACTS CLI self-test
node packages/ifacts-harness/bin/ifacts.mjs --self-test
```

All tests and fixture validations must pass cleanly before opening a Pull Request.

## Contribution Workflow

1. **Fork & Branch**: Fork `https://github.com/ChainMode/iFay.git` and create a topic branch from `main` (for example, `feat/sdk-helper` or `docs/quickstart-clarification`).
2. **Conventional Commits**: Format commit titles following Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`), keeping each commit focused and atomic.
3. **Sign Off Your Commits (DCO 1.1)**: Commit with `git commit -s` so every commit includes a valid `Signed-off-by` line.
4. **Pull Request**: Open a Pull Request against `main` describing the problem, design rationale, and verification output.

## Developer Certificate of Origin v1.1 (DCO 1.1) & Licensing

We use the **Developer Certificate of Origin Version 1.1 (DCO 1.1)** (`https://developercertificate.org/`). **No separate CLA (Contributor License Agreement) is required.**

Every commit must carry a `Signed-off-by` trailer matching your real name and email address (`git commit -s`):

```text
Signed-off-by: Jane Doe <jane.doe@example.com>
```

By signing off, you certify under DCO 1.1 that you have the right to submit the contribution under our **Inbound = Outbound** dual-track open-source licenses (`Copyright (c) 2025-2026 ChainMode contributors`):

- **Code, Schemas, Fixtures & Packages** (`packages/`, `schema/`, `releases/`): Licensed under the **MIT License** ([LICENSE](./LICENSE)).
- **Specifications, Blueprints & Tutorials** (`docs/`): Licensed under **Creative Commons Attribution 4.0 International (CC BY 4.0)** ([LICENSE-DOCS](./LICENSE-DOCS)).

## Ecosystem Terminology Alignment

To preserve semantic clarity across all documentation, schemas, and code comments, please follow these canonical terms:

- **`Human Prime` (`人类原型`)**: Always use `Human Prime` (`人类原型`) to refer to the living human individual paired with an `iFay`.
- **`Host` (`宿主`)**: Use `Host` (`宿主`) strictly for terminal hardware devices, operating systems, or runtime application environments.
- **`Fay = iFay + coFay`**: Use `Fay` as the umbrella term, `iFay` for an individual's personal avatar, and `coFay` for a chartered public or organizational role avatar.
- **`GMChain` (`公誉链`) & `MeriToken (μ)` (`美誉值`)**: Use `GMChain` (`公誉链`) for the Global Merit Chain and `MeriToken` (measured in `μ` / `Merit Unit`) strictly as a non-monetary measure of social contribution.
