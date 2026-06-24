"""leakguard command-line interface.

  leakguard scan [PATH ...]      scan files/dirs (default: .)
  leakguard scan --staged        scan git staged content (pre-commit hook)
  leakguard github --org ACME    scan an org's public repos (post-publish audit)

Optional AI layers (need the `leakguard[ai]` extra; see leakguard/ai.py):
  --presidio   add a Microsoft Presidio PII pass (local)
  --review     ask a LOCAL OpenAI-compatible LLM to flag misses (local-first)

Exit codes: 0 = clean / below threshold, 1 = findings at-or-above --fail-on,
2 = usage/config error. Detection only; leakguard never edits your content.
"""
import argparse
import json
import sys

from . import __version__
from .engine import load_rules, severity_at_least
from .fsscan import scan_paths, scan_staged
from .github_scan import scan_github

SEV_COLOR = {"high": "31", "medium": "33", "low": "36"}  # ansi red/yellow/cyan


def _print_text(findings, scanned, label, use_color):
    by_file = {}
    for f in findings:
        by_file.setdefault(f.path, []).append(f)
    for path in sorted(by_file):
        print(f"\n{path}")
        for f in sorted(by_file[path], key=lambda x: (x.line, x.rule_id)):
            sev = f.severity.upper()
            if use_color:
                sev = f"\033[{SEV_COLOR.get(f.severity, '0')}m{sev}\033[0m"
            print(f"  {f.line}:{f.column} [{sev}] {f.rule_id}: {f.match}"
                  + (f"  -> {f.suggestion}" if f.suggestion else ""))
    n = len(findings)
    print(f"\nleakguard: {n} finding(s) across {scanned} file(s) scanned ({label}).")


def _emit(findings, scanned, label, fmt, fail_on, use_color):
    relevant = [f for f in findings if severity_at_least(f.severity, fail_on)]
    if fmt == "json":
        print(json.dumps({
            "label": label, "files_scanned": scanned,
            "finding_count": len(findings),
            "blocking_count": len(relevant), "fail_on": fail_on,
            "findings": [f.as_dict() for f in findings],
        }, indent=2))
    else:
        if findings:
            _print_text(findings, scanned, label, use_color)
        else:
            print(f"leakguard: clean - 0 findings across {scanned} file(s) ({label}).")
        if relevant:
            print(f"leakguard: {len(relevant)} finding(s) at or above '{fail_on}' "
                  f"-> failing.", file=sys.stderr)
    return 1 if relevant else 0


def _add_common(p):
    p.add_argument("--rules", action="append", default=[],
                   help="extra rules JSON file (repeatable). Private/org rules go here.")
    p.add_argument("--no-builtin", action="store_true",
                   help="disable the built-in generic patterns")
    p.add_argument("--fail-on", choices=["low", "medium", "high"], default="medium",
                   help="minimum severity that causes a non-zero exit (default: medium)")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--presidio", action="store_true",
                   help="add a Microsoft Presidio PII pass (needs leakguard[ai])")
    p.add_argument("--review", action="store_true",
                   help="ask a LOCAL OpenAI-compatible LLM to flag missed leaks "
                        "(configure via LEAKGUARD_LLM_BASE / LEAKGUARD_LLM_MODEL)")


def _build_ai_hook(args, allow):
    """Construct the optional per-file AI hook, or None. Imported lazily so the
    zero-dependency core is untouched when the AI flags are not used."""
    if not (getattr(args, "presidio", False) or getattr(args, "review", False)):
        return None
    from . import ai
    return ai.make_hook(args.presidio, args.review, allow)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    ap = argparse.ArgumentParser(prog="leakguard", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"leakguard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="scan local files/dirs or git staged content")
    sp.add_argument("paths", nargs="*", default=["."])
    sp.add_argument("--staged", action="store_true", help="scan git staged content")
    _add_common(sp)

    gh = sub.add_parser("github", help="scan published GitHub repos (read-only)")
    gh.add_argument("--org", action="append", default=[])
    gh.add_argument("--user", action="append", default=[])
    gh.add_argument("--repo", action="append", default=[], help="owner/name")
    gh.add_argument("--include-private", action="store_true")
    _add_common(gh)

    args = ap.parse_args(argv)
    use_color = (not args.no_color) and sys.stdout.isatty()

    try:
        scan_root = "."
        if args.cmd == "scan" and not args.staged and args.paths:
            scan_root = args.paths[0]
        rules, allow = load_rules(args.rules, use_builtin=not args.no_builtin,
                                  scan_root=scan_root)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"leakguard: rule load error: {e}", file=sys.stderr)
        return 2
    if not rules:
        print("leakguard: no rules loaded (used --no-builtin with no --rules?)",
              file=sys.stderr)
        return 2

    ai_hook = _build_ai_hook(args, allow)

    if args.cmd == "scan":
        if args.staged:
            findings, scanned = scan_staged(rules, allow, ai_hook=ai_hook)
            label = "git staged"
        else:
            findings, scanned = scan_paths(args.paths, rules, allow,
                                           root=scan_root, ai_hook=ai_hook)
            label = "filesystem"
    else:  # github
        if not (args.org or args.user or args.repo):
            print("leakguard github: need --org, --user, or --repo", file=sys.stderr)
            return 2
        findings, repos, scanned, errors = scan_github(
            rules, allow, args.org, args.user, args.repo, args.include_private,
            ai_hook=ai_hook)
        label = f"{repos} repo(s)"
        for e in errors[:10]:
            print(f"leakguard: scan note: {e}", file=sys.stderr)

    return _emit(findings, scanned, label, args.format, args.fail_on, use_color)


if __name__ == "__main__":
    sys.exit(main())
