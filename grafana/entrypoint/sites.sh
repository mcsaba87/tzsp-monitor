#!/bin/sh
# Turns the REMOTE_SITE_* lines of properties.yml into one InfluxDB datasource
# per remote tzsp-monitor, then hands over to the image's own /run.sh.
#
#   REMOTE_SITE_<NAME>=<influxdb url> [token] [org]
#   REMOTE_GRAFANA_<NAME>=<that site's Grafana url>     (optional, for links)
#   LOCAL_SITE_NAME=<what this instance is called in the Site dropdown>
#
# The dashboards pick a site with a datasource variable, so a remote site is
# nothing more than a datasource with the same bucket and schema behind it --
# no data is copied anywhere. Token and org default to the stack's dev
# credentials, which is what an untouched remote install uses.
#
# Generated rather than written by hand because Grafana's provisioning can
# expand an environment variable into a value but cannot expand a list. The
# bind-mounted provisioning directory is copied to a scratch path first, so the
# generated file never lands in the git checkout; dashboards.yml points at the
# mounted path by absolute name, so dashboard edits are still live.
set -euf  # -f: no globbing when a site line is split into fields

SRC=/etc/grafana/provisioning
DST=/tmp/grafana-provisioning
DEFAULT_TOKEN=my-super-secret-token
DEFAULT_ORG=my-org

rm -rf "$DST"
mkdir -p "$DST"
cp -r "$SRC"/. "$DST"/

valid_name() {
    case "$1" in
        ""|*[!A-Za-z0-9\ ._-]*) return 1 ;;
    esac
}

# The local datasource keeps its pinned uid -- every dashboard, and the
# "is this the local site" test in rule-control and dns-resolver, hang off it --
# so only its display name changes. A rename is safe because Grafana's database
# is not a volume: any change to properties.yml recreates the container.
LOCAL_NAME=InfluxDB_Flux
if [ -n "${LOCAL_SITE_NAME:-}" ]; then
    if valid_name "$LOCAL_SITE_NAME"; then
        LOCAL_NAME=$LOCAL_SITE_NAME
        sed -i "s/^  - name: InfluxDB_Flux\$/  - name: \"$LOCAL_NAME\"/" \
            "$DST/datasources/datasource.yml"
    else
        echo "[sites] LOCAL_SITE_NAME='$LOCAL_SITE_NAME' ignored: use letters, digits, space . _ -"
    fi
fi
echo "[sites] local: $LOCAL_NAME (uid InfluxDB_Flux)"

# Every site, local first, as "uid<TAB>name" -- what the overview is built from.
SITES="$DST/sites.tsv"
printf 'InfluxDB_Flux\t%s\n' "$LOCAL_NAME" > "$SITES"

OUT="$DST/datasources/sites.yml"
printf 'apiVersion: 1\n\ndatasources:\n' > "$OUT"
names="|$LOCAL_NAME|Infinity|"
count=0

# Sorted, so the dropdown order does not depend on the order of the env.
for var in $(env | sed -n 's/^\(REMOTE_SITE_[A-Za-z0-9_]*\)=.*/\1/p' | sort); do
    eval "line=\${$var}"
    # shellcheck disable=SC2086  # word splitting is the point: url token org
    set -- $line
    url=${1:-}
    token=${2:-$DEFAULT_TOKEN}
    org=${3:-$DEFAULT_ORG}
    name=$(echo "${var#REMOTE_SITE_}" | tr '_' ' ')
    uid=site-$(echo "${var#REMOTE_SITE_}" | tr 'A-Z_' 'a-z-')

    case "$url" in
        http://*|https://*) ;;
        *) echo "[sites] $var skipped: '$url' is not an http(s) URL"; continue ;;
    esac
    case "$url$token$org" in
        *\"*|*\\*|*\$*) echo "[sites] $var skipped: \", \\ or \$ in the value"; continue ;;
    esac
    case "$names" in
        *"|$name|"*) echo "[sites] $var skipped: '$name' is already a datasource name"; continue ;;
    esac
    names="$names$name|"

    cat >> "$OUT" <<EOF
  - name: "$name"
    type: influxdb
    uid: "$uid"
    access: proxy
    url: "$url"
    jsonData:
      version: Flux
      organization: "$org"
      defaultBucket: network_traffic
    secureJsonData:
      token: "$token"
    isDefault: false
EOF
    printf '%s\t%s\n' "$uid" "$name" >> "$SITES"
    count=$((count + 1))
    echo "[sites] remote: $name -> $url (uid $uid, org $org)"
done

if [ "$count" -eq 0 ]; then
    rm -f "$OUT"
    echo "[sites] no REMOTE_SITE_* entries: this Grafana shows the local site only"
fi

# --- Sites Overview ----------------------------------------------------------
# One dashboard summing every site. A panel cannot fan one query out over a
# multi-value datasource variable (tested on Grafana 13: it runs once, against
# one site), so each panel needs one target per site, and the site list is only
# known here. The template marks those targets as single lines containing
# __UID__; each is repeated once per site, with "@<file>.flux" replaced by that
# query file as a JSON string. Edit the template or the .flux files, then
# `docker compose restart grafana` -- a restart re-runs this script.
GEN=/tmp/grafana-generated
rm -rf "$GEN"
mkdir -p "$GEN"
awk -v sites="$SITES" -v dir=/opt/tzsp/overview -f /opt/tzsp/overview/expand.awk \
    /opt/tzsp/overview/sites_overview.json > "$GEN/sites_overview.json"

cat >> "$DST/dashboards/dashboards.yml" <<EOF

  # Added by sites.sh: the generated Sites Overview, which lives outside the
  # mounted directory so it never lands in the checkout. It joins the Overview
  # folder by title -- with folderUid as well, Grafana logs "the same folder
  # UID is used more than once" on every poll.
  - name: 'Generated'
    orgId: 1
    folder: '1 · Overview'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: $GEN
      foldersFromFilesStructure: false
EOF
echo "[sites] Sites Overview generated for $((count + 1)) site(s)"

# Links to the other sites' Grafana, for the boards whose controls act on this
# instance only (Packet Capture). Served from public/, read back by Infinity.
mkdir -p /usr/share/grafana/public/tzsp
sh /opt/tzsp/sites-links.sh /usr/share/grafana/public/tzsp/sites.json \
    || echo "[sites] could not write the other sites' links; continuing"

# Non-fatal: a Grafana release that moved its logo still starts, with its own.
sh /opt/tzsp/branding.sh || echo "[branding] failed; continuing with Grafana's logo"

export GF_PATHS_PROVISIONING="$DST"
exec /run.sh "$@"
