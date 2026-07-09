#!/bin/bash
# scripts/install-agentxd.sh — Deploy smartmon-snmp-agentx to the local system
#
# Installs the Python AgentX agent (smartmon_agentx.py), the systemd unit,
# YAML config, and MIB files.  Must be run as root.
#
# Usage:
#   sudo scripts/install-agentxd.sh [OPTIONS]
#
# Options:
#   --prefix PREFIX      Installation prefix (default: /usr)
#   --state-dir DIR      JSON state directory (default: /run/smartmontools/json)
#   -h, --help           Show this help
#
# After installation the agent can be started with:
#   systemctl enable --now smartmon-snmp-agentx
#
# Data sources (pick one):
#   * collect mode (default) — the agent polls smartctl directly; no separate
#     collector is installed.  Set `collect: true` in the config (the shipped
#     template already does).
#   * smartd --jsonstate — add to /etc/smartd.conf:
#       DEVICESCAN -x --jsonstate /run/smartmontools/json/
#     then set state_dir to match and `collect: false` (requires smartd >= 7.0
#     for -x).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

PREFIX="/usr"
STATE_DIR="/run/smartmontools/json"
STATE_DB="/var/lib/smartmontools/snmp-agent/snmp-agentx-state.db"

# Installed agent executable, systemd unit, config, and man page names.
AGENT_NAME="smartmon-snmp-agentx"
AGENT_SRC="$REPO_ROOT/smartmon_agentx.py"

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)      PREFIX="$2";       shift 2 ;;
        --state-dir)   STATE_DIR="$2";    shift 2 ;;
        -h|--help)
            sed -n '2,/^set -/p' "$0" | grep '^#' | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

# ---------------------------------------------------------------------------
# Require root
# ---------------------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root." >&2
    echo "  sudo $0 $*" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Locate the Python agent
# ---------------------------------------------------------------------------
if [ ! -f "$AGENT_SRC" ]; then
    echo "ERROR: agent script not found at $AGENT_SRC" >&2
    exit 1
fi

SBINDIR="${PREFIX}/sbin"
SYSCONFDIR="/etc"
UNITDIR="/lib/systemd/system"
MIBDIR="/usr/share/snmp/mibs"
CONFDIR="$SYSCONFDIR/smartmontools"
MAN_SRC="$REPO_ROOT/man"
SYSTEMD_SRC="$REPO_ROOT/systemd"

echo "=== Installing $AGENT_NAME ==="
echo "  agent       : $AGENT_SRC"
echo "  prefix      : $PREFIX"
echo "  state_dir   : $STATE_DIR"
echo ""

# ---------------------------------------------------------------------------
# Python runtime dependencies (python3-netsnmpagent + PyYAML)
# ---------------------------------------------------------------------------
echo "--- installing Python dependencies ---"
install_python_deps() {
    if command -v apt-get &>/dev/null; then
        apt-get install -y --no-install-recommends \
            python3 python3-netsnmpagent python3-yaml snmp smartmontools sudo \
            2>/dev/null || true
    elif command -v dnf &>/dev/null; then
        dnf install -y python3 net-snmp-python python3-pyyaml \
            net-snmp smartmontools sudo 2>/dev/null || true
    elif command -v yum &>/dev/null; then
        yum install -y python3 net-snmp-python python3-pyyaml \
            net-snmp smartmontools sudo 2>/dev/null || true
    fi
}
install_python_deps
if ! python3 -c 'import netsnmpagent' 2>/dev/null; then
    echo "" >&2
    echo "ERROR: the python3-netsnmpagent module is not importable." >&2
    echo "Install it via your package manager (python3-netsnmpagent) or:" >&2
    echo "  pip3 install netsnmpagent" >&2
    exit 1
fi
echo "  python3-netsnmpagent OK"

# ---------------------------------------------------------------------------
# Dedicated system user
# ---------------------------------------------------------------------------
echo "--- creating system user ---"
if ! id smartmon &>/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "$AGENT_NAME daemon" smartmon
    echo "  created user: smartmon"
else
    echo "  user already exists: smartmon"
fi

# Detect the group snmpd uses for the AgentX socket (distro-dependent).
# Debian/Ubuntu use 'Debian-snmp'; RHEL/Fedora use 'snmp'.
SNMP_GROUP=""
for g in Debian-snmp snmp; do
    if getent group "$g" &>/dev/null; then
        SNMP_GROUP="$g"
        break
    fi
done

# Add smartmon to the snmpd group so it can write to /var/agentx/master.
if [ -n "$SNMP_GROUP" ]; then
    usermod -aG "$SNMP_GROUP" smartmon
    echo "  added smartmon to $SNMP_GROUP group (for AgentX socket access)"
else
    echo "  WARNING: no snmpd group found (Debian-snmp / snmp); add smartmon manually" >&2
fi

# ---------------------------------------------------------------------------
# Grant the daemon passwordless smartctl (collect mode)
# ---------------------------------------------------------------------------
# In collect mode the agent runs as the unprivileged 'smartmon' user and shells
# out to 'sudo -n smartctl' to read SMART data.  Install a sudoers drop-in so
# that escalation works without a password.  The grant is limited to the six
# read-only invocations the agent actually issues — device scan, the idle/
# standby power-mode probe (both are granted since older agent builds still
# issue '-n standby'), and SMART/FARM data reads — so destructive smartctl
# subcommands (-t self-test, --set, drive security/sanitize) are NOT runnable
# as root via this rule.  The candidate file is validated with 'visudo -cf'
# before it is moved into place, so a malformed entry can never lock sudo out
# of /etc/sudoers.d.
SMARTCTL_PATH="$(command -v smartctl 2>/dev/null || echo /usr/sbin/smartctl)"
SUDOERS_FILE="/etc/sudoers.d/smartmon-agentx"
SUDOERS_TMP="$(mktemp)"
printf '# smartmon-snmp-agentx: collect mode runs read-only smartctl as root.\n# Managed by install-agentxd.sh (scan + idle/standby probe + SMART/FARM data reads only).\nsmartmon ALL=(root) NOPASSWD: %s --scan-open, %s --scan, %s -x -j *, %s -l farm -j *, %s -n idle -i -j *, %s -n standby -i -j *\n' "$SMARTCTL_PATH" "$SMARTCTL_PATH" "$SMARTCTL_PATH" "$SMARTCTL_PATH" "$SMARTCTL_PATH" "$SMARTCTL_PATH" > "$SUDOERS_TMP"
if visudo -cf "$SUDOERS_TMP" >/dev/null 2>&1; then
    install -m 0440 -o root -g root "$SUDOERS_TMP" "$SUDOERS_FILE"
    echo "  installed sudoers: $SUDOERS_FILE (smartmon -> $SMARTCTL_PATH)"
else
    echo "  WARNING: generated sudoers failed visudo validation; not installed" >&2
fi
rm -f "$SUDOERS_TMP"

# ---------------------------------------------------------------------------
# State directory (writable by root/collect, readable by smartmon user)
# ---------------------------------------------------------------------------
echo "--- creating state directory ---"
install -d -m 750 -o root -g smartmon "$STATE_DIR"
echo "  $STATE_DIR (mode 750, root:smartmon)"
install -d -m 750 -o smartmon -g smartmon "$(dirname "$STATE_DB")"
echo "  $(dirname "$STATE_DB") (mode 750, smartmon:smartmon)"

# ---------------------------------------------------------------------------
# Agent script
# ---------------------------------------------------------------------------
echo "--- installing agent ---"
install -d "$SBINDIR"
# Install the Python script as an executable (it carries a python3 shebang).
install -m 755 "$AGENT_SRC" "$SBINDIR/$AGENT_NAME"
echo "  $SBINDIR/$AGENT_NAME"

# ---------------------------------------------------------------------------
# Man page (substitute @variables@ from the .in source)
# ---------------------------------------------------------------------------
MAN_IN="$MAN_SRC/$AGENT_NAME.8.in"
if [ -f "$MAN_IN" ]; then
    MANDIR="${PREFIX}/share/man/man8"
    install -d "$MANDIR"
    sed -e "s|@sysconfdir@|${SYSCONFDIR}|g" \
        -e "s|@PACKAGE_VERSION@|local|g" \
        "$MAN_IN" > "$MANDIR/$AGENT_NAME.8"
    chmod 644 "$MANDIR/$AGENT_NAME.8"
    echo "  $MANDIR/$AGENT_NAME.8"
fi

# ---------------------------------------------------------------------------
# Config file (YAML; do not overwrite existing)
# ---------------------------------------------------------------------------
echo "--- installing config ---"
install -d "$CONFDIR"
CONF_DEST="$CONFDIR/snmp-agentx.yaml"
CONF_SRC="$REPO_ROOT/etc/$AGENT_NAME.yaml"
if [ -f "$CONF_DEST" ]; then
    echo "  $CONF_DEST already exists — not overwriting"
elif [ -f "$CONF_SRC" ]; then
    # Install the template, patching the state_dir and state_db paths.
    sed -e "s|^state_dir:.*|state_dir: $STATE_DIR|" \
        -e "s|^state_db:.*|state_db: $STATE_DB|" \
        "$CONF_SRC" > "$CONF_DEST"
    chmod 640 "$CONF_DEST"
    chown root:smartmon "$CONF_DEST"
    echo "  $CONF_DEST (new)"
else
    echo "  WARNING: config template not found at $CONF_SRC" >&2
fi

# ---------------------------------------------------------------------------
# MIB files
# ---------------------------------------------------------------------------
echo "--- installing MIB files ---"
install -d "$MIBDIR"
for mib in "$REPO_ROOT"/doc/SMARTMON-*.mib; do
    [ -f "$mib" ] || continue
    install -m 644 "$mib" "$MIBDIR/"
    echo "  $MIBDIR/$(basename "$mib")"
done

# ---------------------------------------------------------------------------
# systemd units
# ---------------------------------------------------------------------------
echo "--- installing systemd units ---"
install -d "$UNITDIR"

# agentx service (substitute @variables@)
UNIT_SRC="$SYSTEMD_SRC/$AGENT_NAME.service.in"
UNIT_DEST="$UNITDIR/$AGENT_NAME.service"
if [ -f "$UNIT_SRC" ]; then
    sed \
        -e "s|@sbindir@|${SBINDIR}|g" \
        -e "s|@sysconfdir@|${SYSCONFDIR}|g" \
        "$UNIT_SRC" > "$UNIT_DEST"
    # Patch the state_dir path in the ReadOnlyPaths line
    sed -i "s|/run/smartmontools/json|${STATE_DIR}|g" "$UNIT_DEST"
    chmod 644 "$UNIT_DEST"
    echo "  $UNIT_DEST"
fi

systemctl daemon-reload

# ---------------------------------------------------------------------------
# snmpd AgentX configuration
# ---------------------------------------------------------------------------
SNMPD_CONF=""
for candidate in /etc/snmp/snmpd.conf /etc/snmpd/snmpd.conf; do
    [ -f "$candidate" ] && SNMPD_CONF="$candidate" && break
done
if [ -n "$SNMPD_CONF" ]; then
    NEED_SNMPD_RESTART=0

    AGENTX_GROUP="${SNMP_GROUP:-snmp}"
    if ! grep -qE "^[[:space:]]*master[[:space:]]+agentx" "$SNMPD_CONF"; then
        printf '\n# Added by install-agentxd.sh\nmaster agentx\nagentxsocket /var/agentx/master\nagentxperms 0660 0550 root %s\n' "$AGENTX_GROUP" >> "$SNMPD_CONF"
        echo "  $SNMPD_CONF: added master agentx + agentxperms (group: $AGENTX_GROUP)"
        NEED_SNMPD_RESTART=1
    elif ! grep -qE "^[[:space:]]*agentxperms[[:space:]]" "$SNMPD_CONF"; then
        printf '\nagentxperms 0660 0550 root %s\n' "$AGENTX_GROUP" >> "$SNMPD_CONF"
        echo "  $SNMPD_CONF: added agentxperms 0660 0550 root $AGENTX_GROUP"
        NEED_SNMPD_RESTART=1
    else
        echo "  $SNMPD_CONF: AgentX already configured"
    fi

    [ "$NEED_SNMPD_RESTART" -eq 1 ] && systemctl restart snmpd && echo "  restarted snmpd"

    # Fix /var/agentx/ directory: snmpd may leave it drwx------ (root:root).
    # Subagents need execute permission on the directory to connect to the socket.
    AGENTX_DIR="/var/agentx"
    if [ -d "$AGENTX_DIR" ]; then
        chown "root:$AGENTX_GROUP" "$AGENTX_DIR"
        chmod 750 "$AGENTX_DIR"
        echo "  $AGENTX_DIR: set root:$AGENTX_GROUP 750"
    fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "=== Installation complete ==="
echo ""
echo "Collect mode (default — the agent polls smartctl directly):"
echo "  systemctl enable --now $AGENT_NAME"
echo ""
echo "To use smartd --jsonstate instead:"
echo "  Add to /etc/smartd.conf:  DEVICESCAN -x -a (requires smartd >= 7.0)"
echo "  Set collect: false and state_dir in $CONF_DEST to match --jsonstate path"
echo "  Then: systemctl enable --now $AGENT_NAME"
echo ""
echo "Verify:"
echo '  snmpwalk -v2c -c public localhost 1.3.6.1.4.1.65891.1.1.2'
echo '  snmpwalk -v2c -c public -m ALL localhost SMARTMON-COMMON-MIB::smartmonDeviceMetadataTable'
echo ""
echo "MIBs installed to $MIBDIR"
