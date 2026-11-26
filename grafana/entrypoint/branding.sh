#!/bin/sh
# Replaces Grafana's logo with tzsp-monitor's, at every container start.
#
# Grafana OSS has no setting for this -- custom branding is an Enterprise
# feature -- so the image's own asset files are overwritten instead. That is
# safe only because the container is disposable: a recreate or an image bump
# brings the originals back, and this runs again before Grafana starts.
#
# The menu logo and the login logo are one file, bundled by webpack under a
# hashed name (static/img/grafana_icon.<hash>.svg) that changes with every
# Grafana release, hence the glob. It stays an .svg because it is served as
# image/svg+xml; logo_icon.svg is the square logo embedded as a data URI, which
# an <img>-loaded SVG is allowed to render (an external href it is not).
#
# Browsers cache the hashed file as immutable, so a page that has already seen
# the Grafana logo needs one hard refresh.
set -eu

SRC=/opt/tzsp/branding
PUB=/usr/share/grafana/public

replaced=0
for f in "$PUB"/build/static/img/grafana_icon.*.svg "$PUB"/img/grafana_icon.svg; do
    [ -f "$f" ] || continue
    cp "$SRC/logo_icon.svg" "$f"
    replaced=$((replaced + 1))
done
cp "$SRC/fav32.png" "$PUB/img/fav32.png"
cp "$SRC/apple-touch-icon.png" "$PUB/img/apple-touch-icon.png"
# The home dashboard's banner, at a URL a text panel can reach.
cp "$SRC/logo_wide.jpg" "$PUB/img/tzsp-monitor.jpg"

if [ "$replaced" -eq 0 ]; then
    echo "[branding] no grafana_icon*.svg found: this Grafana keeps its own logo"
else
    echo "[branding] logo replaced in $replaced file(s)"
fi
