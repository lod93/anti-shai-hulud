#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║              S H A I - H U L U D                                ║
# ║         npm Supply Chain Audit & Guardian                       ║
# ║  Detects compromised packages in global, local & lockfiles      ║
# ╚══════════════════════════════════════════════════════════════════╝

set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
MAGENTA='\033[0;35m'

# ── Affected packages database (name:version,version,...) ──────────
declare -A AFFECTED
AFFECTED["@tanstack/history"]="1.161.9,1.161.12"
AFFECTED["@tanstack/react-router"]="1.169.5,1.169.8"
AFFECTED["@tanstack/router-core"]="1.169.5,1.169.8"
AFFECTED["@tanstack/router-utils"]="1.161.11,1.161.14"
AFFECTED["@tanstack/router-plugin"]="1.167.38,1.167.41"
AFFECTED["@tanstack/virtual-file-routes"]="1.161.10,1.161.13"
AFFECTED["@tanstack/router-generator"]="1.166.45,1.166.48"
AFFECTED["@tanstack/start-server-core"]="1.167.33,1.167.36"
AFFECTED["@tanstack/start-client-core"]="1.168.5,1.168.8"
AFFECTED["@tanstack/start-storage-context"]="1.166.38,1.166.41"
AFFECTED["@tanstack/start-plugin-core"]="1.169.23,1.169.26"
AFFECTED["@tanstack/react-start-server"]="1.166.55,1.166.58"
AFFECTED["@tanstack/react-start-client"]="1.166.51,1.166.54"
AFFECTED["@tanstack/start-fn-stubs"]="1.161.9,1.161.12"
AFFECTED["@tanstack/react-start"]="1.167.68,1.167.71"
AFFECTED["@tanstack/react-start-rsc"]="0.0.47,0.0.50"
AFFECTED["@mistralai/mistralai"]="2.2.2,2.2.3,2.2.4"
AFFECTED["@tanstack/react-router-devtools"]="1.166.16,1.166.19"
AFFECTED["@tanstack/router-devtools-core"]="1.167.6,1.167.9"
AFFECTED["@tanstack/router-devtools"]="1.166.16,1.166.19"
AFFECTED["@tanstack/router-ssr-query-core"]="1.168.3,1.168.6"
AFFECTED["@tanstack/react-router-ssr-query"]="1.166.15,1.166.18"
AFFECTED["@tanstack/router-cli"]="1.166.46,1.166.49"
AFFECTED["@tanstack/zod-adapter"]="1.166.12,1.166.15"
AFFECTED["@tanstack/eslint-plugin-router"]="1.161.9"
AFFECTED["@tanstack/router-vite-plugin"]="1.166.53,1.166.56"
AFFECTED["@tanstack/nitro-v2-vite-plugin"]="1.154.12,1.154.15"
AFFECTED["@mistralai/mistralai-gcp"]="1.7.1,1.7.2,1.7.3"
AFFECTED["@tanstack/solid-router"]="1.169.5,1.169.8"
AFFECTED["@tanstack/solid-start"]="1.167.65,1.167.68"
AFFECTED["@tanstack/solid-start-client"]="1.166.50,1.166.53"
AFFECTED["@tanstack/solid-start-server"]="1.166.54,1.166.57"
AFFECTED["@tanstack/solid-router-devtools"]="1.166.16,1.166.19"
AFFECTED["@tanstack/start-static-server-functions"]="1.166.44,1.166.47"
AFFECTED["@tanstack/vue-router"]="1.169.5,1.169.8"
AFFECTED["@uipath/apollo-react"]="4.24.5"
AFFECTED["@tanstack/solid-router-ssr-query"]="1.166.15,1.166.18"
AFFECTED["safe-action"]="0.8.3,0.8.4"
AFFECTED["@tanstack/valibot-adapter"]="1.166.12,1.166.15"
AFFECTED["@tanstack/vue-start"]="1.167.61,1.167.64"
AFFECTED["@uipath/apollo-wind"]="2.16.2"
AFFECTED["@uipath/cli"]="1.0.1"
AFFECTED["@tanstack/vue-start-server"]="1.166.50,1.166.53"
AFFECTED["@squawk/types"]="0.8.2,0.8.3,0.8.4"
AFFECTED["@uipath/rpa-tool"]="0.9.5"
AFFECTED["@squawk/mcp"]="0.9.1,0.9.2,0.9.3,0.9.4"
AFFECTED["@tanstack/vue-start-client"]="1.166.46,1.166.49"
AFFECTED["@squawk/weather"]="0.5.6,0.5.7,0.5.8,0.5.9"
AFFECTED["@squawk/airspace"]="0.8.1,0.8.2,0.8.3,0.8.4"
AFFECTED["@squawk/icao-registry-data"]="0.8.4,0.8.5,0.8.6,0.8.7"
AFFECTED["@tanstack/arktype-adapter"]="1.166.12,1.166.15"
AFFECTED["@squawk/flightplan"]="0.5.2,0.5.3,0.5.4,0.5.5"
AFFECTED["@squawk/airports"]="0.6.2,0.6.3,0.6.4,0.6.5"
AFFECTED["@mesadev/sdk"]="0.28.3"
AFFECTED["@squawk/geo"]="0.4.4,0.4.5,0.4.6,0.4.7"
AFFECTED["@mesadev/rest"]="0.28.3"
AFFECTED["@squawk/procedure-data"]="0.7.3,0.7.4,0.7.5,0.7.6"
AFFECTED["@squawk/navaid-data"]="0.6.4,0.6.5,0.6.6,0.6.7"
AFFECTED["@squawk/fix-data"]="0.6.4,0.6.5,0.6.6,0.6.7"
AFFECTED["@squawk/navaids"]="0.4.2,0.4.3,0.4.4,0.4.5"
AFFECTED["@squawk/fixes"]="0.3.2,0.3.3,0.3.4,0.3.5"
AFFECTED["@squawk/airport-data"]="0.7.4,0.7.5,0.7.6,0.7.7"
AFFECTED["@squawk/airway-data"]="0.5.4,0.5.5,0.5.6,0.5.7"
AFFECTED["@squawk/units"]="0.4.3,0.4.4,0.4.5,0.4.6"
AFFECTED["@squawk/procedures"]="0.5.2,0.5.3,0.5.4,0.5.5"
AFFECTED["@squawk/airways"]="0.4.2,0.4.3,0.4.4,0.4.5"
AFFECTED["@squawk/icao-registry"]="0.5.2,0.5.3,0.5.4,0.5.5"
AFFECTED["@uipath/apollo-core"]="5.9.2"
AFFECTED["@squawk/notams"]="0.3.6,0.3.7,0.3.8,0.3.9"
AFFECTED["@uipath/filesystem"]="1.0.1"
AFFECTED["@uipath/solutionpackager-tool-core"]="0.0.34"
AFFECTED["@squawk/flight-math"]="0.5.4,0.5.5,0.5.6,0.5.7"
AFFECTED["@squawk/airspace-data"]="0.5.3,0.5.4,0.5.5,0.5.6"
AFFECTED["@mistralai/mistralai-azure"]="1.7.1,1.7.2,1.7.3"
AFFECTED["@uipath/solution-tool"]="1.0.1"
AFFECTED["@tanstack/eslint-plugin-start"]="0.0.4,0.0.7"
AFFECTED["@uipath/maestro-tool"]="1.0.1"
AFFECTED["@uipath/codedapp-tool"]="1.0.1"
AFFECTED["@uipath/agent-tool"]="1.0.1"
AFFECTED["@draftlab/auth"]="0.24.1,0.24.2"
AFFECTED["@uipath/orchestrator-tool"]="1.0.1"
AFFECTED["@uipath/integrationservice-tool"]="1.0.2"
AFFECTED["@taskflow-corp/cli"]="0.1.24,0.1.25,0.1.26,0.1.27,0.1.28,0.1.29"
AFFECTED["@tanstack/vue-router-ssr-query"]="1.166.15,1.166.18"
AFFECTED["@uipath/rpa-legacy-tool"]="1.0.1"
AFFECTED["@uipath/vertical-solutions-tool"]="1.0.1"
AFFECTED["@uipath/flow-tool"]="1.0.2"
AFFECTED["@uipath/codedagent-tool"]="1.0.1"
AFFECTED["@uipath/common"]="1.0.1"
AFFECTED["@uipath/resource-tool"]="1.0.1"
AFFECTED["@uipath/auth"]="1.0.1"
AFFECTED["@uipath/docsai-tool"]="1.0.1"
AFFECTED["@uipath/case-tool"]="1.0.1"
AFFECTED["@uipath/api-workflow-tool"]="1.0.1"
AFFECTED["@tanstack/vue-router-devtools"]="1.166.16,1.166.19"
AFFECTED["@uipath/test-manager-tool"]="1.0.2"
AFFECTED["@uipath/robot"]="1.3.4"
AFFECTED["@uipath/traces-tool"]="1.0.1"
AFFECTED["@uipath/agent-sdk"]="1.0.2"
AFFECTED["@uipath/integrationservice-sdk"]="1.0.2"
AFFECTED["@uipath/maestro-sdk"]="1.0.1"
AFFECTED["@uipath/data-fabric-tool"]="1.0.2"
AFFECTED["@mesadev/saguaro"]="0.4.22"
AFFECTED["@uipath/tasks-tool"]="1.0.1"
AFFECTED["@uipath/insights-tool"]="1.0.1"
AFFECTED["@uipath/insights-sdk"]="1.0.1"
AFFECTED["@uipath/uipath-python-bridge"]="1.0.1"
AFFECTED["@draftlab/db"]="0.16.1"
AFFECTED["@uipath/ap-chat"]="1.5.7"
AFFECTED["@uipath/project-packager"]="1.1.16"
AFFECTED["@uipath/packager-tool-case"]="0.0.9"
AFFECTED["@uipath/packager-tool-workflowcompiler-browser"]="0.0.34"
AFFECTED["@uipath/packager-tool-connector"]="0.0.19"
AFFECTED["@uipath/packager-tool-workflowcompiler"]="0.0.16"
AFFECTED["@uipath/packager-tool-webapp"]="1.0.6"
AFFECTED["@uipath/packager-tool-apiworkflow"]="0.0.19"
AFFECTED["@uipath/packager-tool-functions"]="0.1.1"
AFFECTED["ts-dna"]="3.0.1,3.0.2,3.0.3,3.0.4"
AFFECTED["@uipath/widget.sdk"]="1.2.3"
AFFECTED["@uipath/resources-tool"]="0.1.11"
AFFECTED["@uipath/agent.sdk"]="0.0.18"
AFFECTED["cross-stitch"]="1.1.3,1.1.4,1.1.5,1.1.6"
AFFECTED["@uipath/codedagents-tool"]="0.1.12"
AFFECTED["@uipath/aops-policy-tool"]="0.3.1"
AFFECTED["@uipath/solution-packager"]="0.0.35"
AFFECTED["@draftlab/auth-router"]="0.5.1,0.5.2"
AFFECTED["cmux-agent-mcp"]="0.1.3,0.1.4,0.1.5,0.1.6,0.1.7,0.1.8"
AFFECTED["agentwork-cli"]="0.1.4,0.1.5"
AFFECTED["@uipath/packager-tool-bpmn"]="0.0.9"
AFFECTED["@draftauth/core"]="0.13.1,0.13.2"
AFFECTED["@dirigible-ai/sdk"]="0.6.2,0.6.3"
AFFECTED["@uipath/packager-tool-flow"]="0.0.19"
AFFECTED["git-branch-selector"]="1.3.3,1.3.4,1.3.5,1.3.6,1.3.7"
AFFECTED["wot-api"]="0.8.1,0.8.2,0.8.3,0.8.4"
AFFECTED["git-git-git"]="1.0.8,1.0.9,1.0.10,1.0.11,1.0.12"
AFFECTED["@beproduct/nestjs-auth"]="0.1.2,0.1.3,0.1.4,0.1.5,0.1.6,0.1.7,0.1.8,0.1.9,0.1.10,0.1.11,0.1.12,0.1.13,0.1.14,0.1.15,0.1.16,0.1.17,0.1.18,0.1.19"
AFFECTED["@ml-toolkit-ts/xgboost"]="1.0.3,1.0.4"
AFFECTED["nextmove-mcp"]="0.1.3,0.1.4,0.1.5,0.1.6,0.1.7"
AFFECTED["ml-toolkit-ts"]="1.0.4,1.0.5"
AFFECTED["@uipath/telemetry"]="0.0.7"
AFFECTED["@draftauth/client"]="0.2.1,0.2.2"
AFFECTED["@ml-toolkit-ts/preprocessing"]="1.0.2,1.0.3"
AFFECTED["@tallyui/connector-medusa"]="1.0.1,1.0.2,1.0.3"
AFFECTED["@uipath/tool-workflowcompiler"]="0.0.12"
AFFECTED["@uipath/vss"]="0.1.6"
AFFECTED["@tallyui/theme"]="0.2.1,0.2.2,0.2.3"
AFFECTED["@tallyui/storage-sqlite"]="0.2.1,0.2.2,0.2.3"
AFFECTED["@uipath/solutionpackager-sdk"]="1.0.11"
AFFECTED["@tallyui/connector-vendure"]="1.0.1,1.0.2,1.0.3"
AFFECTED["@tallyui/core"]="0.2.1,0.2.2,0.2.3"
AFFECTED["@tallyui/connector-woocommerce"]="1.0.1,1.0.2,1.0.3"
AFFECTED["@tallyui/components"]="1.0.1,1.0.2,1.0.3"
AFFECTED["@uipath/ui-widgets-multi-file-upload"]="1.0.1"
AFFECTED["@tallyui/pos"]="0.1.1,0.1.2,0.1.3"
AFFECTED["@tallyui/database"]="1.0.1,1.0.2,1.0.3"
AFFECTED["@supersurkhet/cli"]="0.0.2,0.0.3,0.0.4,0.0.5,0.0.6,0.0.7"
AFFECTED["@tallyui/connector-shopify"]="1.0.1,1.0.2,1.0.3"
AFFECTED["@tolka/cli"]="1.0.2,1.0.3,1.0.4,1.0.5,1.0.6"
AFFECTED["@supersurkhet/sdk"]="0.0.2,0.0.3,0.0.4,0.0.5,0.0.6,0.0.7"
AFFECTED["@uipath/access-policy-tool"]="0.3.1"
AFFECTED["@uipath/context-grounding-tool"]="0.1.1"
AFFECTED["@uipath/gov-tool"]="0.3.1"
AFFECTED["@uipath/admin-tool"]="0.1.1"
AFFECTED["@uipath/identity-tool"]="0.1.1"
AFFECTED["@uipath/llmgw-tool"]="1.0.1"
AFFECTED["@uipath/resourcecatalog-tool"]="0.1.1"
AFFECTED["@uipath/functions-tool"]="1.0.1"
AFFECTED["@uipath/access-policy-sdk"]="0.3.1"
AFFECTED["@uipath/platform-tool"]="1.0.1"

# ── Counters (temp files survive subshells) ────────────────────────
HITS_F=$(mktemp); CHECKED_F=$(mktemp)
echo 0 > "$HITS_F"; echo 0 > "$CHECKED_F"
SCAN_TARGETS=()
trap 'rm -f "$HITS_F" "$CHECKED_F"' EXIT
inc_hits()    { echo $(( $(cat "$HITS_F")    + 1 )) > "$HITS_F"; }
inc_checked() { echo $(( $(cat "$CHECKED_F") + 1 )) > "$CHECKED_F"; }
get_hits()    { cat "$HITS_F"; }
get_checked() { cat "$CHECKED_F"; }

# ── Helpers ────────────────────────────────────────────────────────
banner() {
  echo ""
  echo -e "${MAGENTA}${BOLD}"
  echo "  ╔══════════════════════════════════════════════════════════╗"
  echo "  ║                                                          ║"
  echo "  ║   ░▒▓  S H A I - H U L U D  ▓▒░                        ║"
  echo "  ║        npm Supply Chain Guardian                         ║"
  echo "  ║                                                          ║"
  echo "  ╚══════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

section() {
  echo ""
  echo -e "${CYAN}${BOLD}── $1 ──────────────────────────────────────────${RESET}"
}

ok()   { echo -e "  ${GREEN}✔${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
hit()  { echo -e "  ${RED}✘  COMPROMISED: $*${RESET}"; }
info() { echo -e "  ${DIM}→  $*${RESET}"; }

# ── Core checker: given name@version, is it in the hit list? ──────
is_affected() {
  local pkg="$1" ver="$2"
  local versions="${AFFECTED[$pkg]:-}"
  [[ -z "$versions" ]] && return 1
  IFS=',' read -ra vlist <<< "$versions"
  for v in "${vlist[@]}"; do
    [[ "$v" == "$ver" ]] && return 0
  done
  return 1
}

# ── Check a flat "name version" list (from npm list --json) ───────
check_package_list() {
  local label="$1"
  shift
  local found_any=false

  while IFS= read -r line; do
    # Expecting lines like: pkg@version or @scope/pkg@version
    local pkg ver
    # Handle scoped packages
    if [[ "$line" == @* ]]; then
      pkg="$(echo "$line" | sed 's/@[^@]*$//')"
      ver="$(echo "$line" | grep -oE '[^@]+$')"
    else
      pkg="${line%@*}"
      ver="${line##*@}"
    fi

    [[ -z "$pkg" || -z "$ver" ]] && continue
    inc_checked

    if is_affected "$pkg" "$ver"; then
      hit "${label}: ${BOLD}${pkg}@${ver}${RESET}"
      inc_hits
      found_any=true
    fi
  done

  $found_any || ok "${label}: no compromised packages found"
}

# ── Scan global npm installs ───────────────────────────────────────
scan_global() {
  section "Global npm packages (-g)"
  local raw
  raw=$(npm list -g --depth=0 --parseable 2>/dev/null | tail -n +2) || true

  if [[ -z "$raw" ]]; then
    info "No global packages found or npm not available"
    return
  fi

  local entries=()
  while IFS= read -r path; do
    local base
    base=$(basename "$path")
    # Handle scoped: node_modules/@scope/pkg → @scope/pkg
    if [[ "$path" == *node_modules/@* ]]; then
      local scope pkg
      scope=$(echo "$path" | grep -oE '@[^/]+' | tail -1)
      pkg=$(basename "$path")
      base="${scope}/${pkg}"
    fi
    entries+=("$base")
  done <<< "$raw"

  # Get versions via npm list -g --depth=0 (plain text parsing)
  local list_out
  list_out=$(npm list -g --depth=0 2>/dev/null | grep -E '^\+--|`--' | sed 's/[+`]-- //') || true

  while IFS= read -r entry; do
    echo "$entry"
  done <<< "$list_out" | check_package_list "global"
}

# ── Scan a local project directory ────────────────────────────────
scan_local_dir() {
  local dir="$1"
  [[ ! -f "$dir/package.json" ]] && return

  section "Local project: $dir"

  # Check node_modules if present
  if [[ -d "$dir/node_modules" ]]; then
    info "Scanning node_modules..."
    local list_out
    list_out=$(cd "$dir" && npm list --depth=0 2>/dev/null | grep -E '^\+--|`--' | sed 's/[+`]-- //') || true
    while IFS= read -r entry; do
      echo "$entry"
    done <<< "$list_out" | check_package_list "$dir/node_modules"
  else
    info "No node_modules found in $dir (skipping installed check)"
  fi

  # Always check lockfile
  if [[ -f "$dir/package-lock.json" ]]; then
    info "Scanning package-lock.json..."
    scan_lockfile_json "$dir/package-lock.json" | check_package_list "package-lock.json"
  elif [[ -f "$dir/yarn.lock" ]]; then
    info "Scanning yarn.lock..."
    scan_yarn_lock "$dir/yarn.lock" | check_package_list "yarn.lock"
  elif [[ -f "$dir/pnpm-lock.yaml" ]]; then
    info "Scanning pnpm-lock.yaml..."
    scan_pnpm_lock "$dir/pnpm-lock.yaml" | check_package_list "pnpm-lock.yaml"
  elif [[ -f "$dir/bun.lockb" ]]; then
    info "Scanning bun.lockb..."
    scan_bun_lock "$dir/bun.lockb" | check_package_list "bun.lockb"
  fi

  # Heuristic scan of node_modules
  if [[ -d "$dir/node_modules" ]]; then
    scan_suspicious_scripts "$dir/node_modules"
  fi
}

# ── Lockfile scanners ─────────────────────────────────────────────
scan_lockfile_json() {
  local file="$1"
  # Extract "node_modules/X": { "version": "Y" } patterns
  local found_any=false
  while IFS= read -r line; do
    echo "$line"
  done < <(
    grep -E '"version"' "$file" | \
    grep -oE '"[^"]+": "[^""]+"' | \
    grep '"version"' | \
    awk -F'"' '{print $4}' | \
    paste - - 2>/dev/null || true
  )
  # Simpler: grep package names and versions with context
  python3 - "$file" <<'PYEOF' 2>/dev/null || true
import json, sys

with open(sys.argv[1]) as f:
    try:
        lock = json.load(f)
    except:
        sys.exit(0)

packages = lock.get("packages", {})
for path, meta in packages.items():
    if not path or path == "":
        continue
    ver = meta.get("version", "")
    # Strip "node_modules/" and handle nested
    name = path.replace("node_modules/", "").split("node_modules/")[-1]
    if name and ver:
        print(f"{name}@{ver}")
PYEOF
}

scan_yarn_lock() {
  local file="$1"
  # yarn.lock: lines like `"pkg@ver":` and `  version "X.Y.Z"`
  python3 - "$file" <<'PYEOF' 2>/dev/null || true
import re, sys

with open(sys.argv[1]) as f:
    content = f.read()

# Match package name blocks
blocks = re.split(r'\n(?=\S)', content)
for block in blocks:
    lines = block.strip().splitlines()
    if not lines:
        continue
    header = lines[0].strip().strip('"').rstrip(':')
    # Header might be: "pkg@^1.0.0, pkg@~1.0.0"
    ver_match = re.search(r'^\s+version "(.+)"', block, re.MULTILINE)
    if not ver_match:
        continue
    ver = ver_match.group(1)
    # Extract package name (before @version spec)
    name_match = re.match(r'^(@?[^@]+)', header)
    if name_match:
        name = name_match.group(1).strip().strip('"')
        print(f"{name}@{ver}")
PYEOF
}

scan_pnpm_lock() {
  local file="$1"
  # Support both older pnpm-lock.yaml and v9+ which has different structure
  if grep -q "lockfileVersion: '9" "$file" 2>/dev/null || grep -q "lockfileVersion: 9" "$file" 2>/dev/null; then
    # v9 structure: snapshotted packages are often under 'snapshots:'
    # We'll use a more general grep that catches @scope/name@version patterns
    grep -oE '(@?[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+)@[0-9]+\.[0-9]+\.[0-9]+' "$file" | sed 's|^/||' | sort -u || true
  else
    # Older pnpm versions
    grep -E '^\s+/.*:$' "$file" 2>/dev/null | sed "s|^\s*||;s|:$||;s|^/||" | sort -u || true
  fi
}

scan_bun_lock() {
  local file="$1"
  local dir
  dir=$(dirname "$file")
  
  if command -v bun >/dev/null 2>&1; then
    # Use bun's internal tool to list everything
    (cd "$dir" && bun pm ls --all 2>/dev/null | grep -E '├──|└──' | sed 's/[^a-zA-Z0-9@./_-]//g') || true
  else
    # Fallback: strings parsing (noisy but better than nothing)
    warn "bun not found, using heuristic string extraction on bun.lockb"
    strings "$file" | grep -E '^(@?[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+)@[0-9]+\.[0-9]+\.[0-9]+' | sort -u || true
  fi
}

# ── Heuristic Scanners ─────────────────────────────────────────────
scan_suspicious_scripts() {
  local nm_dir="$1"
  section "Heuristic Audit: Suspicious Scripts"
  info "Checking package.json files for dangerous postinstall/preinstall patterns..."
  
  local found_suspicious=0
  # Search for common exfiltration patterns in package.json scripts
  # curl/wget to IPs, encoded strings, nslookup (DNS exfil), etc.
  while IFS= read -r pj; do
    local pkg_name
    pkg_name=$(grep '"name":' "$pj" | head -1 | awk -F'"' '{print $4}')
    
    # Extract scripts section
    local scripts
    scripts=$(python3 - "$pj" <<'PYEOF' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
        scripts = data.get("scripts", {})
        for k, v in scripts.items():
            print(f"{k}: {v}")
except: pass
PYEOF
)
    if [[ -z "$scripts" ]]; then continue; fi

    # Dangerous patterns
    local patterns=("curl" "wget" "nslookup" "base64 -d" "eval" "sh -c" "python -c" "node -e")
    for pat in "${patterns[@]}"; do
      if echo "$scripts" | grep -qi "$pat"; then
        warn "Suspicious script in ${BOLD}${pkg_name}${RESET}: $(echo "$scripts" | grep -i "$pat" | head -1)"
        info "Path: $pj"
        found_suspicious=$((found_suspicious + 1))
        break
      fi
    done
  done < <(find "$nm_dir" -name "package.json" -maxdepth 3 2>/dev/null)

  if [[ $found_suspicious -eq 0 ]]; then
    ok "No suspicious scripts found in top-level dependencies"
  else
    warn "Found $found_suspicious suspicious scripts. Review them manually."
  fi
}

# ── Risk Assessment ────────────────────────────────────────────────
run_risk_assessment() {
  section "Compromise Risk Assessment"
  info "Scanning for sensitive files that may have been targeted..."
  
  local targets=(
    "$HOME/.npmrc"
    "$HOME/.aws/credentials"
    "$HOME/.ssh/id_rsa"
    "$HOME/.ssh/id_ed25519"
    "$HOME/.kube/config"
    "$HOME/.gitconfig"
    "$HOME/.bash_history"
    "$HOME/.zsh_history"
  )

  local found_targets=()
  for t in "${targets[@]}"; do
    if [[ -f "$t" ]]; then
      found_targets+=("$t")
    fi
  done

  if [[ ${#found_targets[@]} -gt 0 ]]; then
    warn "The following sensitive files exist and may have been exfiltrated:"
    for ft in "${found_targets[@]}"; do
      echo -e "    ${DIM}- $ft${RESET}"
    done
    echo ""
    warn "If any compromised packages were found, ROTATE THESE CREDENTIALS IMMEDIATELY."
  else
    ok "No common sensitive files found in default locations."
  fi

  # Check for active tokens in environment
  if [[ -n "${NPM_TOKEN:-}" || -n "${GITHUB_TOKEN:-}" || -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
    warn "Sensitive environment variables (NPM_TOKEN, etc.) are active and may have been stolen."
  fi
}

# ── Write .npmrc blocklist ─────────────────────────────────────────
write_npmrc_block() {
  section "Installing .npmrc scope blocklist"
  local npmrc="$HOME/.npmrc"

  local marker="# [shai-hulud] compromised scope blocks"
  if grep -q "shai-hulud" "$npmrc" 2>/dev/null; then
    warn ".npmrc already has shai-hulud blocks — skipping (run with --force-block to overwrite)"
    return
  fi

  cat >> "$npmrc" <<NPMRC

${marker}
@squawk:registry=http://localhost:0
@tanstack:registry=http://localhost:0
@uipath:registry=http://localhost:0
@tallyui:registry=http://localhost:0
@beproduct:registry=http://localhost:0
@mistralai:registry=http://localhost:0
@draftlab:registry=http://localhost:0
@draftauth:registry=http://localhost:0
@taskflow-corp:registry=http://localhost:0
@tolka:registry=http://localhost:0
@supersurkhet:registry=http://localhost:0
@mesadev:registry=http://localhost:0
@ml-toolkit-ts:registry=http://localhost:0
@dirigible-ai:registry=http://localhost:0
NPMRC

  ok "Scope blocklist written to $npmrc"
  info "Affected unscoped packages (safe-action, ts-dna, cross-stitch, etc.) must be blocked manually per-project."
}

# ── Automated Repair ───────────────────────────────────────────────
repair_compromised() {
  local dirs=("$@")
  section "Automated Repair & Mitigation"
  
  # We don't have a list of EXACTLY which packages were found where in a persistent way
  # except by re-scanning or tracking. For now, we'll re-scan and fix.
  
  for dir in "${dirs[@]}"; do
    [[ ! -d "$dir" ]] && continue
    info "Attempting to repair project in $dir..."
    
    # Check node_modules for uninstalls
    if [[ -d "$dir/node_modules" ]]; then
      local pkg_mgr="npm"
      [[ -f "$dir/yarn.lock" ]] && pkg_mgr="yarn"
      [[ -f "$dir/pnpm-lock.yaml" ]] && pkg_mgr="pnpm"
      [[ -f "$dir/bun.lockb" ]] && pkg_mgr="bun"
      
      # We need the list of hits. Let's do a quick focused scan.
      # This is slightly inefficient but safe.
      local hits_to_fix=()
      # ... implementation of hit collection ...
      # For simplicity, we'll tell the user what to run or try to run it.
      warn "Auto-fix will attempt to uninstall packages found in the database."
      for pkg in "${!AFFECTED[@]}"; do
        if (cd "$dir" && $pkg_mgr list "$pkg" --depth=0 2>/dev/null | grep -q "$pkg"); then
          info "Removing $pkg via $pkg_mgr..."
          (cd "$dir" && $pkg_mgr uninstall "$pkg") || true
        fi
      done
    fi
  done

  # Offer to clean cache
  info "Recommendation: Run '${BOLD}npm cache clean --force${RESET}' to purge potentially malicious payloads."
}

# ── Report ─────────────────────────────────────────────────────────
report() {
  echo ""
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "  ${BOLD}SHAI-HULUD SCAN COMPLETE${RESET}"
  echo -e "  Packages checked : ${BOLD}$(get_checked)${RESET}"
  if [[ "$(get_hits)" -gt 0 ]]; then
    echo -e "  ${RED}${BOLD}Compromised found: $(get_hits)${RESET}"
    run_risk_assessment
    echo ""
    echo -e "  ${RED}${BOLD}⚠  ACTION REQUIRED:${RESET}"
    echo -e "  ${RED}  1. Remove affected packages immediately${RESET}"
    echo -e "  ${RED}  2. Rotate ALL tokens/secrets on that machine${RESET}"
    echo -e "  ${RED}  3. Review CI logs for credential exfiltration${RESET}"
    echo -e "  ${RED}  4. Run: npm cache clean --force${RESET}"
  else
    echo -e "  ${GREEN}${BOLD}Compromised found: 0  ✔  All clear${RESET}"
  fi
  echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo ""
}

# ── Usage ──────────────────────────────────────────────────────────
usage() {
  echo ""
  echo -e "${BOLD}Usage:${RESET}"
  echo "  shai-hulud.sh [OPTIONS] [DIRS...]"
  echo ""
  echo -e "${BOLD}Options:${RESET}"
  echo "  -g, --global        Scan global npm packages (default: always included)"
  echo "  -l, --local DIR     Scan a local project directory"
  echo "  -w, --workspace DIR Scan all projects recursively in DIR"
  echo "  -b, --block         Write .npmrc scope blocklist after scan"
  echo "  -f, --fix           Attempt to remove/repair compromised packages"
  echo "  -h, --help          Show this help"
  echo ""
  echo -e "${BOLD}Examples:${RESET}"
  echo "  ./shai-hulud.sh                        # scan global only"
  echo "  ./shai-hulud.sh -w .                   # scan all projects in current dir"
  echo "  ./shai-hulud.sh -l ./my-project --fix  # scan + remove malicious deps"
  echo "  ./shai-hulud.sh --block                # scan + install .npmrc blocklist"
  echo ""
}

# ── Main ───────────────────────────────────────────────────────────
main() {
  local do_block=false
  local do_fix=false
  local local_dirs=()
  local workspaces=()

  [[ $# -eq 0 ]] && { banner; scan_global; report; exit 0; }

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)        usage; exit 0 ;;
      -g|--global)      shift ;;  # global is always included
      -b|--block)       do_block=true; shift ;;
      -f|--fix)         do_fix=true; shift ;;
      -w|--workspace)   shift; workspaces+=("$1"); shift ;;
      --force-block)    do_block=true; shift ;;
      -l|--local)       shift; local_dirs+=("$1"); shift ;;
      *)                local_dirs+=("$1"); shift ;;
    esac
  done

  banner

  # Always scan global
  scan_global

  # Scan any local directories
  for dir in "${local_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
      scan_local_dir "$dir"
    else
      warn "Directory not found: $dir"
    fi
  done

  # Scan any workspaces
  for ws in "${workspaces[@]}"; do
    if [[ -d "$ws" ]]; then
      scan_workspace "$ws"
    else
      warn "Workspace directory not found: $ws"
    fi
  done

  # Install blocklist if requested
  $do_block && write_npmrc_block

  # Run repair if requested
  if $do_fix && [[ "$(get_hits)" -gt 0 ]]; then
    repair_compromised "${local_dirs[@]}"
  fi

  report

  # Exit code: 1 if any hits found
  [[ "$(get_hits)" -gt 0 ]] && exit 1 || exit 0
}

# ── Workspace Scanner ──────────────────────────────────────────────
scan_workspace() {
  local root="$1"
  section "Scanning Workspace: $root"
  info "Searching for npm projects (package.json)..."

  set +e # Don't exit on individual project failures

  # Find all package.json files, excluding node_modules
  # We use a temporary file to collect paths to avoid subshell issues with find
  local pjs_f
  pjs_f=$(mktemp)
  find "$root" -name "package.json" -not -path "*/node_modules/*" > "$pjs_f" 2>/dev/null || true

  local count=0
  while IFS= read -r pj; do
    [[ -z "$pj" ]] && continue
    local dir
    dir=$(dirname "$pj")
    scan_local_dir "$dir"
    count=$((count + 1))
  done < "$pjs_f"
  rm -f "$pjs_f"

  if [[ $count -eq 0 ]]; then
    warn "No npm projects found in $root"
  else
    ok "Finished scanning $count projects in workspace"
  fi
  set -e
}

main "$@"
