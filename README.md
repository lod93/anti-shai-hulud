# 🪱 Shai-Hulud

> *"He who controls the spice controls the universe."*
> Here, the spice is your npm tokens. Don't let them be taken.

**Shai-Hulud** is a zero-dependency bash tool that scans your npm environment for packages compromised in the May 2025 supply chain attack campaign — and blocks future installs of affected scopes.

---

## The Attack

A large-scale npm supply chain campaign published malicious versions of packages across popular scopes including `@tanstack`, `@uipath`, `@squawk`, `@mistralai`, `@tallyui`, `@beproduct`, `@draftlab`, `@taskflow-corp`, and more.

**150+ package-version combos** were identified. These packages target:

- Local developer environments
- CI/CD pipelines and build systems
- Release workflows

...specifically to harvest **npm tokens, GitHub tokens, cloud credentials, Kubernetes service account tokens, and deployment secrets**.

See [`docs/affected-packages.md`](docs/affected-packages.md) for the full list.

---

## Quick Start

```bash
# Download
curl -O https://raw.githubusercontent.com/YOUR_USERNAME/shai-hulud/main/shai-hulud.sh
chmod +x shai-hulud.sh

# Scan your global npm installs
./shai-hulud.sh

# Scan global + a local project (checks node_modules AND lockfile)
./shai-hulud.sh -l ./my-project

# Scan + write .npmrc blocklist to prevent future installs
./shai-hulud.sh --block
```

---

## Usage

```
shai-hulud.sh [OPTIONS] [DIRS...]

Options:
  -g, --global        Scan global npm packages (always included by default)
  -l, --local DIR     Scan a local project directory
  -b, --block         Write .npmrc scope blocklist after scan
  -h, --help          Show this help

Examples:
  ./shai-hulud.sh                        # scan global only
  ./shai-hulud.sh -l ./my-project        # scan global + local project
  ./shai-hulud.sh -l . -l ../other-app   # scan multiple projects
  ./shai-hulud.sh --block                # scan + install .npmrc blocklist
  ./shai-hulud.sh -l . --block           # scan everything + block
```

---

## What It Checks

| Target | How |
|---|---|
| Global `-g` installs | `npm list -g --depth=0` |
| Local `node_modules` | `npm list --depth=0` in project dir |
| `package-lock.json` | Full packages section parsed with Python |
| `yarn.lock` | Version entries extracted per block |
| `pnpm-lock.yaml` | Package path entries parsed |

Lockfile scanning catches compromised versions **even before `npm install` runs** — useful for auditing PRs or freshly cloned repos.

---

## Blocklist Mode

Running with `--block` appends scope-level blocks to your `~/.npmrc`:

```ini
# [shai-hulud] compromised scope blocks
@squawk:registry=http://localhost:0
@tanstack:registry=http://localhost:0
@uipath:registry=http://localhost:0
# ... and more
```

Any install attempt for those scopes will **fail immediately** rather than pulling from the registry. Remove a scope entry once the legitimate maintainers have published clean versions.

> **Note:** Unscoped affected packages (`safe-action`, `ts-dna`, `cross-stitch`, `cmux-agent-mcp`, etc.) are detected in scans but cannot be blocked at the scope level — pin exact known-good versions in your projects.

---

## CI Integration

Shai-Hulud exits with code `1` if any compromised package is found, making it CI-friendly.

**GitHub Actions example:**

```yaml
# .github/workflows/supply-chain-audit.yml
name: Supply Chain Audit
on: [push, pull_request]

jobs:
  shai-hulud:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Shai-Hulud
        run: |
          curl -sSf https://raw.githubusercontent.com/YOUR_USERNAME/shai-hulud/main/shai-hulud.sh \
            -o shai-hulud.sh
          chmod +x shai-hulud.sh
          ./shai-hulud.sh -l .
```

---

## If You Find a Hit

**Take this seriously.** These packages exfiltrate secrets at install time.

1. **Remove the package immediately**: `npm uninstall <package>`
2. **Clean the cache**: `npm cache clean --force`
3. **Rotate ALL credentials** on that machine — npm tokens, GitHub PATs, AWS/GCP keys, kubeconfig tokens
4. **Audit CI logs** for any outbound requests to unknown hosts around the time of install
5. **Check other machines** that may have installed the same dep (shared `package-lock.json`)

---

## Affected Scopes (Summary)

| Scope | Packages affected |
|---|---|
| `@squawk` | 87 package-version entries |
| `@tanstack` | 83 package-version entries |
| `@uipath` | 66 package-version entries |
| `@tallyui` | 30 package-version entries |
| `@beproduct` | 18 package-version entries |
| `@mistralai` | ~9 package-version entries |
| `@draftlab`, `@draftauth`, `@taskflow-corp`, `@tolka` | various |
| Unscoped | 39 package-version entries |

Full list → [`docs/affected-packages.md`](docs/affected-packages.md)

---

## Requirements

- Bash 4+
- Node.js / npm (for live environment scanning)
- Python 3 (for lockfile parsing — available on virtually all systems)

No npm dependencies. No network calls. Runs entirely offline.

---

## Contributing

Found a new affected package? Open an issue or PR against [`docs/affected-packages.md`](docs/affected-packages.md) and the `AFFECTED` array in `shai-hulud.sh`.

Please include:
- Package name and exact compromised versions
- Source/reference (security advisory, blog post, etc.)

---

## License

MIT — use freely, share widely.

---

*Named for the great sandworm of Arrakis. It moves beneath the surface, unseen, until it's too late. So do supply chain attacks.*
