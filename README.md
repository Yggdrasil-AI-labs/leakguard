# leakguard

Catch internal identifiers, secrets, and PII before they leak into public
artifacts. leakguard scans local files, git staged content (as a pre-commit
hook), and already-published GitHub repos, then reports each hit with a line
reference and a suggested fix. It is detection-only: it never edits your content.

## The safety model

The thing most likely to leak from a secret-scanner is its own rule list, because
that list is an inventory of exactly what you are trying to hide. leakguard is
built so that never happens:

- The repo ships **only generic, industry-standard patterns** (cloud keys,
  private-key blocks, RFC1918 / CGNAT addresses, common token formats). These
  contain no organization-specific values.
- Your **organization-specific patterns** (internal hostnames, private project
  names, people, locations) live in a **private rules file you keep out of version
  control**. leakguard loads it at runtime. It is gitignored by default.

So the public tool is useful out of the box, and your real pattern list stays
local.

## Install

```
pip install leakguard         # or: pip install . from a clone
```

Python 3.8+, standard library only (no runtime dependencies).

## Usage

Scan a tree:

```
leakguard scan .
```

Scan only what is staged for commit (used by the pre-commit hook):

```
leakguard scan --staged
```

Audit published repos read-only (an org, a user, or specific repos):

```
leakguard github --org your-org
leakguard github --repo owner/name --repo owner/other
```

Exit code is `0` when clean (or only findings below the threshold) and `1` when
there are findings at or above `--fail-on` (default `medium`), which is what makes
it usable as a CI gate. `--format json` emits machine-readable output.

## Private rules

Copy `rules/example.rules.json` to `.leakguard.local.json` at your repo root (or
anywhere, and point `--rules` / `LEAKGUARD_RULES` at it). It is auto-loaded and
gitignored. Format:

```json
{
  "rules": [
    {"id": "internal-host", "pattern": "\\bacme-[a-z0-9]+\\b",
     "severity": "high", "message": "internal hostname",
     "suggestion": "use a public codename", "flags": "i"}
  ],
  "allow": ["acme-public-handle", "203.0.113.5"]
}
```

`pattern` is a Python regular expression. `severity` is `low`, `medium`, or
`high`. `allow` is a list of literal strings; any match equal to an allow entry
is dropped, which is how you whitelist public names that resemble internal ones.

## Pre-commit hook

```
ln -sf ../../hooks/pre-commit .git/hooks/pre-commit
```

The hook scans staged content and blocks the commit on findings at or above
`LEAKGUARD_FAIL_ON` (default `medium`). Bypass once with `git commit --no-verify`.

## CI

`.github/workflows/leakguard.yml` runs a scan on push and pull request. To use
private patterns in CI, store the rules JSON as a repository secret and write it
to `.leakguard.local.json` in a step before the scan (do not commit it).

## Built-in patterns

Cloud and service credentials (AWS, GCP, GitHub, Slack, Stripe), private-key
blocks, JWTs, hard-coded secret assignments, RFC1918 and CGNAT IP addresses,
Tailscale MagicDNS hostnames, and email addresses. Tune severities or disable the
built-ins with `--no-builtin` and supply your own.

## License

MIT.
