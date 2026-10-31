"""Differential Sigma-conformance harness: banken vs pySigma.

pySigma is the reference *parser*: `.parse()` returns a fully-expanded
condition tree (identifiers inlined, every modifier and value-list turned into
AND/OR/NOT over field/keyword leaves). This script adds a small, faithful
*evaluator* over that tree, synthesises events, and checks banken's verdict
agrees. A divergence is a conformance bug -- in banken, or (rarely) in this
evaluator, to adjudicate.

Scope: fields banken models (Image, CommandLine, ParentImage, TargetFilename,
User, CurrentDirectory) and keywords. A rule touching any other field, or a
shape the generator can't synthesise, is skipped and counted -- honestly.

Run:  uv run conformance.py <rule-dir> [path/to/banken]
"""

import json
import re
import subprocess
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionNOT, ConditionOR

FIELD_MAP = {
    "Image": "image",
    "CommandLine": "commandLine",
    "ParentImage": "parentImage",
    "TargetFilename": "targetFilename",
    "User": "user",
    "CurrentDirectory": "currentDirectory",
}


class Unsupported(Exception):
    pass


def sigmastring_regex(val, anchored):
    """Regex for a pySigma value: a SigmaString's literals+wildcards, or an
    escaped plain value. Case-insensitive, matching Sigma semantics."""
    pre = "(?i)^" if anchored else "(?i)"
    suf = "$" if anchored else ""
    if hasattr(val, "s"):  # SigmaString
        body = "".join(
            re.escape(p) if isinstance(p, str) else (".*" if p.name == "WILDCARD_MULTI" else ".")
            for p in val.s
        )
    else:
        body = re.escape(str(val))
    return pre + body + suf


def concrete(val):
    """A concrete string matching the value (wildcards dropped, literals kept)."""
    if hasattr(val, "s"):
        return "".join(p for p in val.s if isinstance(p, str))
    return str(val)


def leaf_value(node):
    return getattr(node, "value", None)


def eval_node(node, event):
    if isinstance(node, ConditionAND):
        return all(eval_node(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(eval_node(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not eval_node(node.args[0], event)
    val = leaf_value(node)
    if val is None:
        raise Unsupported(type(node).__name__)
    if not hasattr(val, "s"):  # regexp / number / cidr value -- not synthesisable here
        raise Unsupported("value-type")
    field = getattr(node, "field", None)
    if field is None:  # keyword: substring in any field
        rx = sigmastring_regex(val, anchored=False)
        return any(re.search(rx, str(v)) for v in event.values())
    key = FIELD_MAP.get(field)
    if key is None:
        raise Unsupported("field:" + str(field))
    return re.match(sigmastring_regex(val, anchored=True), event.get(key, "")) is not None


def satisfy(node, event):
    """Mutate event so node evaluates True (best-effort; eval_node re-checks)."""
    if isinstance(node, ConditionAND):
        for a in node.args:
            if not isinstance(a, ConditionNOT):
                satisfy(a, event)
        return
    if isinstance(node, ConditionOR):
        for a in node.args:
            if isinstance(a, ConditionNOT):
                continue
            try:
                satisfy(a, event)
                return
            except Unsupported:
                continue
        raise Unsupported("or-branch")
    if isinstance(node, ConditionNOT):
        return  # leave the inner expression unsatisfied (fields stay empty)
    val = leaf_value(node)
    if val is None:
        raise Unsupported(type(node).__name__)
    if not hasattr(val, "s"):  # regexp / number / cidr value -- not synthesisable here
        raise Unsupported("value-type")
    field = getattr(node, "field", None)
    if field is None:  # keyword -> stuff it into the command line
        event["commandLine"] = (event.get("commandLine", "") + " " + concrete(val)).strip()
        return
    key = FIELD_MAP.get(field)
    if key is None:
        raise Unsupported("field:" + str(field))
    event[key] = concrete(val)


def banken_fires(banken, rule_dir, event, rule_name):
    out = subprocess.run(
        [banken, "check", "-rules", str(rule_dir), "-json", json.dumps(event)],
        capture_output=True, text=True, timeout=60,
    )
    # match the exact rule name as a whole word in the output
    return re.search(r"\b" + re.escape(rule_name) + r"\b", out.stdout) is not None


def main():
    if len(sys.argv) < 2:
        sys.exit("usage: conformance.py <rule-dir> [banken]")
    rule_dir = Path(sys.argv[1])
    banken = sys.argv[2] if len(sys.argv) > 2 else "banken"

    parsed = parse_fail = tested = agree = 0
    skipped = {}
    divergences = []

    for path in sorted(rule_dir.rglob("*.yml")):
        try:
            coll = SigmaCollection.from_yaml(path.read_text())
        except Exception:
            parse_fail += 1
            continue
        for rule in coll.rules:
            parsed += 1
            try:
                tree = rule.detection.parsed_condition[0].parse()
                pos = {}
                satisfy(tree, pos)
                # positive must evaluate true, and the empty event is the negative.
                if not eval_node(tree, pos):
                    skipped["gen-nonmatch"] = skipped.get("gen-nonmatch", 0) + 1
                    continue
                neg_expected = eval_node(tree, {})
            except Unsupported as e:
                r = str(e).split()[0].split(":")[0]
                skipped[r] = skipped.get(r, 0) + 1
                continue

            name = path.stem
            for event, expected in ((pos, True), ({}, neg_expected)):
                got = banken_fires(banken, rule_dir, event, name)
                tested += 1
                if got == expected:
                    agree += 1
                else:
                    divergences.append((name, event, expected, got))

    print(f"pySigma parsed {parsed} rules ({parse_fail} files failed to parse)")
    print(f"eval differential: banken agrees with the pySigma-derived evaluator "
          f"on {agree}/{tested} checks" + (f" ({100*agree/tested:.1f}%)" if tested else ""))
    print("skipped (out of this harness's scope), by reason:")
    for r, n in sorted(skipped.items(), key=lambda kv: -kv[1]):
        print(f"  {n:4d}  {r}")
    if divergences:
        print(f"\nDIVERGENCES ({len(divergences)}):")
        for name, event, exp, got in divergences[:25]:
            print(f"  {name}: pySigma={exp} banken={got}  {json.dumps(event)}")
    else:
        print("\nno divergences")
    if divergences:
        sys.exit(1)  # a conformance gate, not just a report


if __name__ == "__main__":
    main()
