#!/bin/bash
# scripts/install-remote.sh — Deploy smartmon-snmp-agentx to a remote host via SSH
#
# Copies the Python agent (smartmon_agentx.py), support scripts, systemd units,
# YAML config, and MIB files to a remote machine, then performs all setup
# (Python deps, user creation, service installation, snmpd config) over SSH.
#
# Usage:
#   scripts/install-remote.sh [OPTIONS] user@host
#
# Options:
#   --prefix PREFIX      Installation prefix on remote (default: /usr)
#   --ssh-key FILE       SSH private key (-i FILE)
#   --port PORT          SSH port (default: 22)
#   --state-dir DIR      JSON state directory on remote
#                        (default: /run/smartmontools/json)
#   --no-collect         Skip installing the smartmon-collect service/timer
#   --dry-run            Print what would be done, without executing
#   -h, --help           Show this help
#
# Requirements:
#   Local:  rsync, ssh (or scp as fallback)
#   Remote: bash, sudo, systemctl, useradd, rsync or scp, and a package
#           manager that provides python3-netsnmpagent (or pip3 fallback)
#
# Examples:
#   # Deploy to ops@server01
#   scripts/install-remote.sh ops@server01
#
#   # Deploy to a non-standard SSH port with a specific key
#   scripts/install-remote.sh --port 2222 --ssh-key ~/.ssh/ops_ed25519 ops@server01
#
#   # Dry run to preview what would happen
#   scripts/install-remote.sh --dry-run ops@server01

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Defaults
PREFIX="/usr"
SSH_KEY=""
SSH_PORT=22
STATE_DIR="/run/smartmontools/json"
STATE_DB="/var/lib/smartmontools/snmp-agent/snmp-agentx-state.db"
INSTALL_COLLECT=1
DRY_RUN=0
REMOTE=""

AGENT_NAME="smartmon-snmp-agentx"
AGENT_SRC="$REPO_ROOT/smartmon_agentx.py"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)       PREFIX="$2";       shift 2 ;;
        --ssh-key)      SSH_KEY="$2";      shift 2 ;;
        --port)         SSH_PORT="$2";     shift 2 ;;
        --state-dir)    STATE_DIR="$2";    shift 2 ;;
        --no-collect)   INSTALL_COLLECT=0; shift   ;;
        --dry-run)      DRY_RUN=1;         shift   ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0 ;;
        -*)
            echo "ERROR: Unknown option: $1" >&2
            echo "Usage: $0 [OPTIONS] user@host" >&2
            exit 1 ;;
        *)
            if [ -n "$REMOTE" ]; then
                echo "ERROR: Multiple hosts specified; only one is allowed." >&2
                exit 1
            fi
            REMOTE="$1"
            shift ;;
    esac
done

if [ -z "$REMOTE" ]; then
    echo "ERROR: No remote host specified." >&2
    echo "Usage: $0 [OPTIONS] user@host" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Locate the Python agent (no build step — it is a self-contained script)
# ---------------------------------------------------------------------------
if [ ! -f "$AGENT_SRC" ]; then
    echo "ERROR: agent script not found at $AGENT_SRC" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# SSH / rsync helpers
# ---------------------------------------------------------------------------
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -p "$SSH_PORT")
[ -n "$SSH_KEY" ] && SSH_OPTS+=(-i "$SSH_KEY")

run_ssh() {
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[DRY-RUN] ssh ${SSH_OPTS[*]} $REMOTE: $*"
    else
        ssh "${SSH_OPTS[@]}" "$REMOTE" "$@"
    fi
}

# Copies a list of local files to a remote directory (requires remote sudo).
# rsync is preferred for efficiency; falls back to scp.
copy_to_remote() {
    local remote_dir="$1"
    shift
    local files=("$@")

    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[DRY-RUN] copy ${files[*]} → $REMOTE:$remote_dir"
        return 0
    fi

    # Use a temp dir on the remote that the SSH user can write without sudo
    local tmp
    tmp=$(run_ssh "mktemp -d /tmp/smartmon-deploy.XXXXXX")

    if command -v rsync &>/dev/null; then
        rsync -az -e "ssh ${SSH_OPTS[*]}" "${files[@]}" "$REMOTE:$tmp/" \
            || { run_ssh "rm -rf '$tmp'" 2>/dev/null || true; return 1; }
    else
        scp "${SSH_OPTS[@]/#-p/-P}" "${files[@]}" "$REMOTE:$tmp/" \
            || { run_ssh "rm -rf '$tmp'" 2>/dev/null || true; return 1; }
    fi

    # Move from the writable temp dir into the final destination as root
    local names=()
    for f in "${files[@]}"; do names+=("$(basename "$f")"); done
    run_ssh "sudo mkdir -p '$remote_dir' && sudo mv ${names[*]/#/$tmp/} '$remote_dir/'"
    run_ssh "rm -rf '$tmp'"
}

# ---------------------------------------------------------------------------
# Assemble the list of files to deploy
# ---------------------------------------------------------------------------
BIN_SRC="$REPO_ROOT/bin"
SYSTEMD_SRC="$REPO_ROOT/systemd"
MAN_SRC="$REPO_ROOT/man"
ETC_SRC="$REPO_ROOT/etc"

AGENT_FILES=("$AGENT_SRC")
[ "$INSTALL_COLLECT" -eq 1 ] && AGENT_FILES+=("$BIN_SRC/smartmon-collect")

SERVICE_FILES=("$SYSTEMD_SRC/$AGENT_NAME.service.in")
[ "$INSTALL_COLLECT" -eq 1 ] && SERVICE_FILES+=(
    "$SYSTEMD_SRC/smartmon-collect.service"
    "$SYSTEMD_SRC/smartmon-collect.timer"
)

MIB_FILES=("$REPO_ROOT"/doc/SMARTMON-*.mib)
CONF_FILE_SRC="$ETC_SRC/$AGENT_NAME.yaml"
MAN_FILE_SRC="$MAN_SRC/$AGENT_NAME.8.in"

echo "=== Remote deployment: $AGENT_NAME ==="
echo "  target       : $REMOTE"
echo "  prefix       : $PREFIX"
echo "  state_dir    : $STATE_DIR"
echo "  state_db     : $STATE_DB"
echo "  ssh port     : $SSH_PORT"
echo "  agent        : $AGENT_SRC"
echo "  install poll : $([ "$INSTALL_COLLECT" -eq 1 ] && echo yes || echo no)"
[ "$DRY_RUN" -eq 1 ] && echo "  *** DRY RUN — no changes will be made ***"
echo ""

# ---------------------------------------------------------------------------
# Pre-flight: verify we can reach the remote
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" -eq 0 ]; then
    echo "--- checking remote connectivity ---"
    if ! run_ssh "true" 2>/dev/null; then
        echo "ERROR: Cannot connect to $REMOTE" >&2
        exit 1
    fi
    echo "  connected"
fi

# ---------------------------------------------------------------------------
# Copy files to remote.  The agent script and config keep their source names
# during transfer; the remote setup step below renames them into place.
# ---------------------------------------------------------------------------
echo "--- copying files ---"

SBINDIR="$PREFIX/sbin"
SYSTEMD_DIR="/etc/systemd/system"
MIB_DIR="/usr/share/snmp/mibs"
STAGE_DIR="/etc/smartmontools"

copy_to_remote "$SBINDIR" "${AGENT_FILES[@]}"
copy_to_remote "$SYSTEMD_DIR" "${SERVICE_FILES[@]}"
[ ${#MIB_FILES[@]} -gt 0 ] && copy_to_remote "$MIB_DIR" "${MIB_FILES[@]}"
[ -f "$CONF_FILE_SRC" ] && copy_to_remote "$STAGE_DIR" "$CONF_FILE_SRC"
[ -f "$MAN_FILE_SRC" ]  && copy_to_remote "$STAGE_DIR" "$MAN_FILE_SRC"

# ---------------------------------------------------------------------------
# Remote configuration and service setup
# ---------------------------------------------------------------------------
echo "--- configuring remote ---"

run_ssh bash -s << REMOTE_SCRIPT
set -euo pipefail

AGENT_NAME="$AGENT_NAME"
SBINDIR="$SBINDIR"
SYSCONFDIR="/etc"
STATE_DIR="$STATE_DIR"
STATE_DB="$STATE_DB"
INSTALL_COLLECT="$INSTALL_COLLECT"
SYSTEMD_DIR="$SYSTEMD_DIR"
STAGE_DIR="$STAGE_DIR"

# ---- Install Python runtime dependencies ---------------------------------
if command -v apt-get &>/dev/null 2>/dev/null; then
    sudo apt-get install -y --no-install-recommends \
        python3 python3-netsnmpagent python3-yaml snmp smartmontools sudo \
        2>/dev/null || true
elif command -v dnf &>/dev/null 2>/dev/null; then
    sudo dnf install -y python3 net-snmp-python python3-pyyaml net-snmp smartmontools sudo 2>/dev/null || true
elif command -v yum &>/dev/null 2>/dev/null; then
    sudo yum install -y python3 net-snmp-python python3-pyyaml net-snmp smartmontools sudo 2>/dev/null || true
fi
if ! python3 -c 'import netsnmpagent' 2>/dev/null; then
    echo "ERROR: python3-netsnmpagent not importable on remote." >&2
    echo "Install it (python3-netsnmpagent) or: pip3 install netsnmpagent" >&2
    exit 1
fi
echo "  python3-netsnmpagent OK"

# ---- Rename the agent script into its final executable name --------------
if [ -f "\$SBINDIR/smartmon_agentx.py" ]; then
    sudo mv -f "\$SBINDIR/smartmon_agentx.py" "\$SBINDIR/\$AGENT_NAME"
    sudo chmod 755 "\$SBINDIR/\$AGENT_NAME"
    echo "  installed \$SBINDIR/\$AGENT_NAME"
fi
[ -f "\$SBINDIR/smartmon-collect" ] && sudo chmod 755 "\$SBINDIR/smartmon-collect"

# ---- Create dedicated system user ----------------------------------------
if ! id smartmon &>/dev/null 2>&1; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "\$AGENT_NAME daemon" smartmon
    echo "  created user: smartmon"
else
    echo "  user already exists: smartmon"
fi

# Detect the group snmpd uses for the AgentX socket (distro-dependent).
# Debian/Ubuntu use 'Debian-snmp'; RHEL/Fedora use 'snmp'.
SNMP_GROUP=""
for g in Debian-snmp snmp; do
    if getent group "\$g" &>/dev/null; then
        SNMP_GROUP="\$g"
        break
    fi
done

# Add smartmon to the snmpd group so it can write to /var/agentx/master.
if [ -n "\$SNMP_GROUP" ]; then
    sudo usermod -aG "\$SNMP_GROUP" smartmon
    echo "  added smartmon to \$SNMP_GROUP group (for AgentX socket access)"
else
    echo "  WARNING: no snmpd group found (Debian-snmp / snmp); add smartmon manually" >&2
fi

# ---- Grant the daemon passwordless smartctl (collect mode) ----------------
# In collect mode the agent runs as the unprivileged 'smartmon' user and shells
# out to 'sudo -n smartctl' to read SMART data.  Install a sudoers drop-in so
# that escalation works without a password.  The grant is limited to the four
# read-only invocations the agent actually issues — device scan plus SMART/FARM
# data reads — so destructive smartctl subcommands (-t self-test, --set, drive
# security/sanitize) are NOT runnable as root via this rule.  The candidate file
# is validated with 'visudo -cf' before it is moved into place, so a malformed
# entry can never lock sudo out of /etc/sudoers.d.
SMARTCTL_PATH="\$(command -v smartctl 2>/dev/null || echo /usr/sbin/smartctl)"
SUDOERS_FILE="/etc/sudoers.d/smartmon-agentx"
SUDOERS_TMP="\$(mktemp)"
printf '# smartmon-snmp-agentx: collect mode runs read-only smartctl as root.\n# Managed by install-remote.sh (scan + SMART/FARM data reads only).\nsmartmon ALL=(root) NOPASSWD: %s --scan-open, %s --scan, %s -x -j *, %s -l farm -j *\n' "\$SMARTCTL_PATH" "\$SMARTCTL_PATH" "\$SMARTCTL_PATH" "\$SMARTCTL_PATH" > "\$SUDOERS_TMP"
if sudo visudo -cf "\$SUDOERS_TMP" >/dev/null 2>&1; then
    sudo install -m 0440 -o root -g root "\$SUDOERS_TMP" "\$SUDOERS_FILE"
    echo "  installed sudoers: \$SUDOERS_FILE (smartmon -> \$SMARTCTL_PATH)"
else
    echo "  WARNING: generated sudoers failed visudo validation; not installed" >&2
fi
rm -f "\$SUDOERS_TMP"

# ---- Create and secure the state directory --------------------------------
sudo mkdir -p "\$STATE_DIR"
sudo chown root:smartmon "\$STATE_DIR"
sudo chmod 750 "\$STATE_DIR"
echo "  state dir: \$STATE_DIR (mode 750, root:smartmon)"

# ---- Create and secure the SQLite state DB directory -----------------------
sudo mkdir -p "\$(dirname "\$STATE_DB")"
sudo chown smartmon:smartmon "\$(dirname "\$STATE_DB")"
sudo chmod 750 "\$(dirname "\$STATE_DB")"
echo "  state DB dir: \$(dirname "\$STATE_DB") (mode 750, smartmon:smartmon)"

# ---- Substitute @variables@ in the service file --------------------------
AGENTX_SVC="\$SYSTEMD_DIR/\$AGENT_NAME.service"
if [ -f "\$AGENTX_SVC.in" ]; then
    sudo sed \
        -e "s|@sbindir@|\$SBINDIR|g" \
        -e "s|@sysconfdir@|\$SYSCONFDIR|g" \
        "\$AGENTX_SVC.in" | sudo tee "\$AGENTX_SVC" > /dev/null
    sudo rm -f "\$AGENTX_SVC.in"
fi

# Patch state dir into the collect service if different from default
if [ "\$INSTALL_COLLECT" = "1" ]; then
    COLLECT_SVC="\$SYSTEMD_DIR/smartmon-collect.service"
    if [ -f "\$COLLECT_SVC" ] && [ "\$STATE_DIR" != "/run/smartmontools/json" ]; then
        sudo sed -i "s|/run/smartmontools/json|\$STATE_DIR|g" "\$COLLECT_SVC"
    fi
fi

# ---- Install the man page (substitute @variables@) ------------------------
MAN_IN="\$STAGE_DIR/\$AGENT_NAME.8.in"
if [ -f "\$MAN_IN" ]; then
    sudo install -d /usr/share/man/man8
    sudo sed -e "s|@sysconfdir@|\$SYSCONFDIR|g" -e "s|@PACKAGE_VERSION@|local|g" \
        "\$MAN_IN" | sudo tee "/usr/share/man/man8/\$AGENT_NAME.8" > /dev/null
    sudo rm -f "\$MAN_IN"
fi

# ---- YAML config file -----------------------------------------------------
CONF_FILE="\$SYSCONFDIR/smartmontools/snmp-agentx.yaml"
CONF_STAGED="\$STAGE_DIR/\$AGENT_NAME.yaml"
sudo mkdir -p "\$(dirname "\$CONF_FILE")"
if [ ! -f "\$CONF_FILE" ] && [ -f "\$CONF_STAGED" ]; then
    sudo sed -e "s|^state_dir:.*|state_dir: \$STATE_DIR|" \
             -e "s|^state_db:.*|state_db: \$STATE_DB|" \
             "\$CONF_STAGED" | sudo tee "\$CONF_FILE" > /dev/null
    sudo chmod 640 "\$CONF_FILE"
    sudo chown root:smartmon "\$CONF_FILE"
    echo "  created config: \$CONF_FILE"
else
    echo "  config present or template missing (not overwritten): \$CONF_FILE"
fi
# Remove the staged template copy
[ -f "\$CONF_STAGED" ] && sudo rm -f "\$CONF_STAGED"

# ---- Harden snmpd.conf ----------------------------------------------------
SNMPD_CONF="\$(find /etc -name snmpd.conf 2>/dev/null | head -1)"
if [ -n "\$SNMPD_CONF" ]; then
    NEED_SNMPD_RESTART=0

    AGENTX_GROUP="\${SNMP_GROUP:-snmp}"
    if ! grep -qE "^[[:space:]]*master[[:space:]]+agentx" "\$SNMPD_CONF"; then
        printf '\n# Added by install-remote.sh\nmaster agentx\nagentxsocket /var/agentx/master\nagentxperms 0660 0550 root %s\n' "\$AGENTX_GROUP" | sudo tee -a "\$SNMPD_CONF" > /dev/null
        echo "  \$SNMPD_CONF: added master agentx + agentxperms (group: \$AGENTX_GROUP)"
        NEED_SNMPD_RESTART=1
    elif ! grep -qE "^[[:space:]]*agentxperms[[:space:]]" "\$SNMPD_CONF"; then
        printf '\nagentxperms 0660 0550 root %s\n' "\$AGENTX_GROUP" | sudo tee -a "\$SNMPD_CONF" > /dev/null
        echo "  \$SNMPD_CONF: added agentxperms 0660 0550 root \$AGENTX_GROUP"
        NEED_SNMPD_RESTART=1
    else
        echo "  \$SNMPD_CONF: AgentX already configured"
    fi

    [ "\$NEED_SNMPD_RESTART" -eq 1 ] && sudo systemctl restart snmpd && echo "  restarted snmpd"

    # Fix /var/agentx/ directory: snmpd may leave it drwx------ (root:root).
    # Subagents need execute permission on the directory to connect to the socket.
    AGENTX_DIR="/var/agentx"
    if [ -d "\$AGENTX_DIR" ]; then
        sudo chown "root:\$AGENTX_GROUP" "\$AGENTX_DIR"
        sudo chmod 750 "\$AGENTX_DIR"
        echo "  \$AGENTX_DIR: set root:\$AGENTX_GROUP 750"
    fi
fi

# ---- Reload and enable services ------------------------------------------
sudo systemctl daemon-reload

if [ "\$INSTALL_COLLECT" = "1" ]; then
    sudo systemctl enable smartmon-collect.timer
    sudo systemctl start  smartmon-collect.timer
    # Run once immediately so data is available before the first timer tick
    sudo systemctl start  smartmon-collect.service
    echo "  enabled and started: smartmon-collect.timer"
fi

sudo systemctl enable "\$AGENT_NAME.service"
sudo systemctl restart "\$AGENT_NAME.service"
echo "  enabled and (re)started: \$AGENT_NAME.service"

echo ""
echo "  Deployment complete.  Verify with:"
echo "    snmpwalk -v2c -c public localhost 1.3.6.1.4.1.65891.1.1.2"
REMOTE_SCRIPT

echo ""
echo "=== Deployment finished ==="
