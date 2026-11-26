#!/bin/sh
# Start Suricata against the TZSP tap.
#
# Three things have to happen before the engine can come up, and all three are
# easy to get wrong silently:
#   1. the tap has to exist. This container shares tzsp-decap's network
#      namespace, and compose only guarantees start order, not that decap has
#      finished creating tzsp0 -- Suricata exits immediately if the interface is
#      missing, and a crash-loop is a lot less obvious than a wait message.
#   2. HOME_NET has to match the site. It is read from the same property file
#      the responder uses, so "my networks" is defined once.
#   3. a ruleset has to be on disk. suricata-update needs the internet; if it
#      fails we start with whatever is in the (persistent) rules volume rather
#      than not starting at all.
set -eu

IFACE="${TAP_INTERFACE:-tzsp0}"
CONFIG="${SURICATA_CONFIG:-/etc/suricata/tzsp/suricata.yaml}"
PROPERTIES="${PROPERTIES_FILE:-/etc/tzsp-monitor/suricata.properties}"
RULE_DIR=/var/lib/suricata/rules
RULE_FILE="$RULE_DIR/suricata.rules"
CONTROL_DIR="${CONTROL_DIR:-/var/lib/suricata-control}"
RULES_MAX_AGE_MIN="${RULES_MAX_AGE_MIN:-1440}"
WAIT_SECONDS="${IFACE_WAIT_SECONDS:-60}"

log() { echo "[entrypoint] $*"; }

# --- 1. wait for the tap ----------------------------------------------------
waited=0
while [ ! -e "/sys/class/net/$IFACE" ]; do
    if [ "$waited" -ge "$WAIT_SECONDS" ]; then
        log "interface $IFACE never appeared after ${WAIT_SECONDS}s."
        log "Is tzsp-decap running, and is this container sharing its network"
        log "namespace (network_mode: service:tzsp-decap)?"
        exit 1
    fi
    [ "$waited" -eq 0 ] && log "waiting for $IFACE (created by tzsp-decap)..."
    sleep 1
    waited=$((waited + 1))
done
log "capture interface $IFACE is present"

# --- 2. HOME_NET ------------------------------------------------------------
home_net="${SURICATA_HOME_NET:-}"
# -f, not -r: a missing bind-mount source makes Docker create a *directory*
# here, and a directory is readable.
if [ -z "$home_net" ] && [ -f "$PROPERTIES" ]; then
    # First non-comment "suricata.home_net = ..." line, value trimmed.
    home_net=$(sed -n 's/^[[:space:]]*suricata\.home_net[[:space:]]*=[[:space:]]*//p' \
               "$PROPERTIES" | head -n 1 | sed 's/[[:space:]]*$//')
fi

set -- -c "$CONFIG" --af-packet
if [ -n "$home_net" ]; then
    log "HOME_NET = $home_net"
    set -- "$@" --set "vars.address-groups.HOME_NET=$home_net"
else
    log "HOME_NET not set in $PROPERTIES; using the default from suricata.yaml"
fi

# --- 3. the shared control directory ----------------------------------------
# Holds threshold.config (rewritten by rule-control when a rule is disabled from
# Grafana) and the unix command socket. Seeded here because Suricata starts
# first and warns about a missing threshold file.
mkdir -p "$CONTROL_DIR"
if [ ! -f "$CONTROL_DIR/threshold.config" ]; then
    cat > "$CONTROL_DIR/threshold.config" <<'EOF'
# Managed by rule-control (see rule-control/control.py). Everything between the
# BEGIN/END markers is rewritten whenever a rule is disabled or re-enabled from
# the Grafana UI -- edit inside them and your change will be lost.
#
# Hand-written thresholds belong ABOVE the markers; they are preserved.
# Syntax: https://docs.suricata.io/en/latest/configuration/global-thresholds.html
# BEGIN rule-control
# END rule-control
EOF
    log "seeded $CONTROL_DIR/threshold.config"
fi

# --- 4. rules ---------------------------------------------------------------
mkdir -p "$RULE_DIR"
if [ -n "$(find "$RULE_FILE" -mmin "-$RULES_MAX_AGE_MIN" 2>/dev/null)" ]; then
    log "ruleset is younger than ${RULES_MAX_AGE_MIN}min, skipping suricata-update"
else
    log "fetching rules with suricata-update..."
    # --no-test: the engine test would re-open the capture interface, and a
    # transient failure there must not stop us from starting with older rules.
    if suricata-update --no-test --suricata-conf "$CONFIG"; then
        log "ruleset updated"
    else
        log "suricata-update failed (no internet?). Continuing with the rules"
        log "already in the volume; only local.rules may be active."
    fi
fi
# Referenced unconditionally by suricata.yaml, so it must exist even if every
# update attempt has failed.
[ -f "$RULE_FILE" ] || : > "$RULE_FILE"
log "$(grep -c '^alert' "$RULE_FILE" 2>/dev/null || echo 0) alert rules in $RULE_FILE"

log "starting suricata: suricata $*"
exec suricata "$@"
