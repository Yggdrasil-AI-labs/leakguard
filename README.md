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

The optional AI layers add dependencies and are installed separately:

```
pip install 'leakguard[ai]'   # presidio-analyzer + spacy
python -m spacy download en_core_web_lg
```

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

## Optional AI layers (`leakguard[ai]`)

Two **local, opt-in** layers supplement the regex engine. They produce the same
findings and flow through the same exit-code path, so they just add coverage on
top of the built-in and private rules. The zero-dependency core keeps working
without them; if the extra is not installed, each layer prints a one-line install
hint and is skipped (it never crashes the scan).

Enable them with flags on either `scan` or `github`:

```
pip install 'leakguard[ai]'
python -m spacy download en_core_web_lg

leakguard scan . --presidio              # Presidio PII pass
leakguard scan . --review                # local-LLM reviewer
leakguard scan . --presidio --review     # both, merged with the regex findings
leakguard github --org your-org --presidio --review
```

### Presidio PII pass (`--presidio`)

Runs Microsoft [Presidio](https://github.com/microsoft/presidio) as a second PII
detector (names, phone numbers, credit cards, SSNs, IBANs, and more). Each
detected entity becomes a finding with `rule_id` `presidio:<ENTITY_TYPE>`; entity
types map to leakguard severities and the engine's `allow` list is honored. Hits
below a confidence threshold are dropped.

| env | default | meaning |
| --- | --- | --- |
| `LEAKGUARD_PRESIDIO_THRESHOLD` | `0.5` | drop hits below this confidence score |
| `LEAKGUARD_PRESIDIO_LANG` | `en` | spaCy language |

### Local-LLM reviewer (`--review`)

Sends each scanned file plus the findings collected so far to a **local
OpenAI-compatible** `/v1/chat/completions` endpoint and asks the model to flag
**misses** the rules and Presidio did not catch. It is model-agnostic and uses
only the standard-library `urllib` (no client dependency). Model-flagged items
become findings with `rule_id` `llm-review`.

Local-first by design: the default endpoint is a localhost server (Ollama's
default port). Pointing it at a remote/cloud endpoint is strictly opt-in via env.

| env | default | meaning |
| --- | --- | --- |
| `LEAKGUARD_LLM_BASE` | `http://localhost:11434/v1` | OpenAI-compatible base URL |
| `LEAKGUARD_LLM_MODEL` | `llama3.1` | model name |
| `LEAKGUARD_LLM_KEY` | _(unset)_ | bearer token, only for endpoints that need auth |
| `LEAKGUARD_LLM_TIMEOUT` | `60` | per-request timeout, seconds |
| `LEAKGUARD_LLM_MAX_CHARS` | `16000` | max chars of a file sent per request |

```
# point at any local OpenAI-compatible server
export LEAKGUARD_LLM_BASE=http://localhost:11434/v1
export LEAKGUARD_LLM_MODEL=qwen2.5-coder
leakguard scan . --review
```

Both layers are detection-only and run locally by default. The LLM reviewer sends
file content to whatever endpoint you configure, so keep it pointed at a local
model unless you have explicitly decided otherwise.

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
