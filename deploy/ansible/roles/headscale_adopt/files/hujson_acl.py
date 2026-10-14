#!/usr/bin/env python3
"""HuJSON-safe check/insert of one ACL rule in a Headscale policy file (F6-007 hs_hook_acl). Runs on the host.

The policy is HuJSON (comments, trailing commas): it is parsed after stripping those, but the rule is inserted
textually right after the `[` of "acls", so every comment and the layout stay as they are. Prints JSON:
{"present": true} when an accept rule with the source and destination already exists (nothing written), else
{"present": false, "written": <out>} after writing the candidate to <out> (never in place).
Usage: hujson_acl.py <policy> <out> <src> <dst>
       hujson_acl.py --probe <policy> <src> <dst>   read-only: prints {"present": true|false}, writes nothing.
       hujson_acl.py --equal <a> <b>   exit 0 when both mean the same policy (comments and layout ignored), else 1.
       Headscale stores a policy with its comments blanked out, so G-02's read-back is compared this way.
"""
import json
import re
import sys


def strip(text):
    """Remove // and /* */ comments outside strings and trailing commas: plain JSON."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\":
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[\]}])", r"\1", "".join(out))


def acls_bracket(text):
    """Index just after the '[' of the top-level "acls" key (outside strings and comments), or -1."""
    i, n, in_str, depth = 0, len(text), False, 0
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == '"':
            if depth == 1 and text.startswith('"acls"', i):
                j = i + len('"acls"')
                m = re.compile(r'\s*:\s*\[').match(text, j)
                if m:
                    return m.end()
            in_str = True
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
        i += 1
    return -1


def has_rule(doc, src, dst):
    for a in doc.get("acls") or []:
        if a.get("action") == "accept" and src in (a.get("src") or []) and dst in (a.get("dst") or []):
            return True
    return False


def main():
    if sys.argv[1] == "--equal":
        a, b = (json.loads(strip(open(p, encoding="utf-8").read())) for p in sys.argv[2:4])
        sys.exit(0 if a == b else 1)
    if sys.argv[1] == "--probe":
        policy, src, dst = sys.argv[2:5]
        doc = json.loads(strip(open(policy, encoding="utf-8").read()))
        print(json.dumps({"present": has_rule(doc, src, dst)}))
        return
    policy, out, src, dst = sys.argv[1:5]
    text = open(policy, encoding="utf-8").read()
    doc = json.loads(strip(text))
    if has_rule(doc, src, dst):
        print(json.dumps({"present": True}))
        return
    rule = '{"action": "accept", "src": ["%s"], "dst": ["%s"]}' % (src, dst)
    comment = "// tagcess installer (hs_hook_acl): the k8s webhook path to the tagcess hook (architecture §8 step 3)"
    at = acls_bracket(text)
    if at >= 0:
        new = text[:at] + "\n    " + comment + "\n    " + rule + "," + text[at:]
    else:
        brace = text.index("{")
        new = text[:brace + 1] + '\n  "acls": [\n    ' + comment + "\n    " + rule + "\n  ]," + text[brace + 1:]
    if not has_rule(json.loads(strip(new)), src, dst):
        raise SystemExit("the inserted rule is not visible after parsing; nothing written")
    with open(out, "w", encoding="utf-8") as f:
        f.write(new)
    print(json.dumps({"present": False, "written": out}))


if __name__ == "__main__":
    main()
