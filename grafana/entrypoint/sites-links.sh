#!/bin/sh
# Writes the other sites' Grafana links as JSON, for the dashboards whose
# controls cannot follow the Site box (Packet Capture first of all):
#
#   REMOTE_SITE_<NAME>=<influxdb url> [token] [org]     (sites.sh)
#   REMOTE_GRAFANA_<NAME>=<that site's Grafana url>     (optional, this file)
#
#   sh sites-links.sh <output.json>
#
# -> [{"site": "BUDAPEST", "uid": "site-budapest",
#      "grafana": "https://grafana.budapest.example",
#      "packet_capture": "https://grafana.budapest.example/d/packet-capture",
#      "note": ""}, ...]
#
# Why a file and not a query: a site's pcap-dump is reachable only from that
# site's own Grafana -- its control API is unpublished and lives in that
# host's capture namespace, on purpose, since publishing it would publish a
# switch that records every cleartext credential. So the honest cross-site
# answer is a link to the other Grafana, and the list of those exists only
# here, at container start. The output is served from Grafana's public/
# directory, which the Infinity datasource reads back server-side; public/
# needs no login, so it holds the site names and Grafana URLs -- nothing a
# login to those Grafanas would not show anyway, and no credentials.
set -euf

OUT=${1:?usage: sites-links.sh <output.json>}
tmp="$OUT.tmp"
printf '[' > "$tmp"
sep=""
count=0

for var in $(env | sed -n 's/^\(REMOTE_SITE_[A-Za-z0-9_]*\)=.*/\1/p' | sort); do
    key=${var#REMOTE_SITE_}
    # Same derivation as sites.sh, so the uid matches the datasource.
    name=$(echo "$key" | tr '_' ' ')
    uid=site-$(echo "$key" | tr 'A-Z_' 'a-z-')
    eval "grafana=\${REMOTE_GRAFANA_$key:-}"
    grafana=${grafana%/}
    note=""
    case "$grafana" in
        "") note="no Grafana URL: set REMOTE_GRAFANA_$key in properties.yml" ;;
        *[!A-Za-z0-9:/._~%-]*)
            echo "[sites] REMOTE_GRAFANA_$key ignored: only a plain http(s) URL is allowed"
            grafana=""; note="REMOTE_GRAFANA_$key is not a plain URL" ;;
        http://*|https://*) ;;
        *)
            echo "[sites] REMOTE_GRAFANA_$key ignored: '$grafana' is not an http(s) URL"
            grafana=""; note="REMOTE_GRAFANA_$key is not an http(s) URL" ;;
    esac
    pc=""
    [ -n "$grafana" ] && pc="$grafana/d/packet-capture"
    printf '%s{"site": "%s", "uid": "%s", "grafana": "%s", "packet_capture": "%s", "note": "%s"}' \
        "$sep" "$name" "$uid" "$grafana" "$pc" "$note" >> "$tmp"
    sep=", "
    count=$((count + 1))
done

# A REMOTE_GRAFANA_ without its REMOTE_SITE_ is a typo worth a line.
for var in $(env | sed -n 's/^\(REMOTE_GRAFANA_[A-Za-z0-9_]*\)=.*/\1/p'); do
    key=${var#REMOTE_GRAFANA_}
    eval "site=\${REMOTE_SITE_$key:-}"
    [ -n "$site" ] || echo "[sites] $var ignored: there is no REMOTE_SITE_$key"
done

printf ']\n' >> "$tmp"
mv "$tmp" "$OUT"
echo "[sites] links to $count other site(s) written to $OUT"
