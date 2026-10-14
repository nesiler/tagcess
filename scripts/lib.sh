# Shared helpers for tagcess scripts. Bash 3.2 compatible (macOS default).

# fm FILE KEY: print a frontmatter value (text after "KEY:", trailing "# comment" removed).
fm() {
  awk -v k="$2" '
    NR == 1 && $0 != "---" { exit }
    NR > 1 && $0 == "---"  { exit }
    NR > 1 && index($0, k ":") == 1 {
      v = substr($0, length(k) + 2)
      sub(/[ \t]+#.*$/, "", v); sub(/^[ \t]+/, "", v); sub(/[ \t]+$/, "", v)
      print v; exit
    }' "$1"
}

# body FILE: print everything after the frontmatter.
body() { awk 'c >= 2 { print; next } $0 == "---" { c++ }' "$1"; }
