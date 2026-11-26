# Expands sites_overview.json into a dashboard for the sites in `sites`
# ("uid<TAB>name" per line, local first). Called by sites.sh.
#
#   a line containing __UID__   -> one copy per site, joined with commas, with
#                                  __UID__/__SITE__ substituted and
#                                  "@<file>.flux" replaced by that file's text
#                                  as a JSON string
#   __SITES_JSON__              -> the site list as an escaped JSON array, for
#                                  the Infinity inline target that keeps an
#                                  unreachable site visible as a row
#
# Site names are already restricted to [A-Za-z0-9 ._-] by sites.sh, so they
# need no escaping of their own.

# Literal replacement: gsub would treat \ and & in the replacement specially.
function repl(s, find, rep,    out, i) {
    out = ""
    while ((i = index(s, find)) > 0) {
        out = out substr(s, 1, i - 1) rep
        s = substr(s, i + length(find))
    }
    return out s
}

function esc(s) {
    s = repl(s, "\\", "\\\\")
    s = repl(s, "\"", "\\\"")
    return repl(s, "\t", "\\t")
}

function flux(name,    line, out, path) {
    path = dir "/" name
    out = ""
    while ((getline line < path) > 0)
        out = out esc(line) "\\n"
    close(path)
    return out
}

BEGIN {
    n = 0
    while ((getline l < sites) > 0) {
        split(l, a, "\t")
        n++
        uid[n] = a[1]
        nm[n] = a[2]
    }
    q = "\\\""
    js = "["
    for (i = 1; i <= n; i++)
        js = js (i > 1 ? "," : "") "{" q "site" q ":" q nm[i] q "," q "site_uid" q ":" q uid[i] q "}"
    js = js "]"
}

index($0, "__UID__") {
    line = $0
    comma = sub(/,[ \t]*$/, "", line)
    if (match(line, /"@[a-z_]+\.flux"/))
        line = substr(line, 1, RSTART) flux(substr(line, RSTART + 2, RLENGTH - 3)) substr(line, RSTART + RLENGTH - 1)
    out = ""
    for (i = 1; i <= n; i++)
        out = out (i > 1 ? ",\n" : "") repl(repl(line, "__UID__", uid[i]), "__SITE__", nm[i])
    print out (comma ? "," : "")
    next
}

{ print repl($0, "__SITES_JSON__", js) }
