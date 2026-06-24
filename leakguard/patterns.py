"""Built-in, GENERIC detection patterns.

These are universal secret/identifier shapes (cloud keys, private keys, private
IP ranges, common token formats). They contain NO organization-specific values.
Anything specific to your infrastructure (internal hostnames, private tool names,
people, locations) belongs in a private rules file loaded at runtime via --rules
or an auto-loaded `.leakguard.local.json` — never here, never in the repo.

Each entry: (id, regex, severity, message, suggestion). Severity is one of
"low" | "medium" | "high".
"""

# (id, pattern, severity, message, suggestion)
BUILTIN_PATTERNS = [
    # ---- credentials / keys ----
    ("aws-access-key-id", r"\bAKIA[0-9A-Z]{16}\b", "high",
     "AWS access key id", "rotate the key and remove it from the artifact"),
    ("gcp-api-key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "high",
     "Google API key", "rotate the key; load it from a secret store"),
    ("github-token", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "high",
     "GitHub token", "revoke the token immediately"),
    ("slack-token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "high",
     "Slack token", "revoke the token"),
    ("stripe-secret-key", r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b", "high",
     "Stripe secret key", "roll the key"),
    ("private-key-block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
     "high", "private key block", "remove the key; never commit private keys"),
    ("jwt", r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b", "medium",
     "JSON Web Token", "tokens often embed claims/PII; do not commit live tokens"),
    ("generic-assignment-secret",
     r"(?i)\b(?:api[_-]?key|secret|passwd|password|token|access[_-]?key)\b\s*[:=]\s*"
     r"['\"][^'\"\s]{8,}['\"]",
     "medium", "hard-coded secret assignment",
     "load from an environment variable or secret store, not source"),
    ("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_+\-]+", "high",
     "Slack incoming webhook URL", "rotate the webhook"),

    # ---- private / non-routable network addresses ----
    # Written so example/doc ranges (RFC5737 203.0.113.x / 192.0.2.x / 198.51.100.x)
    # do NOT match. Lookaround avoids version-string false positives like 1.10.0.0.
    ("private-ip", r"(?<![\d.])(?:"
                   r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                   r"|192\.168\.\d{1,3}\.\d{1,3}"
                   r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                   r")(?![\d.])",
     "medium", "RFC1918 private IP address",
     "replace with an RFC5737 placeholder (203.0.113.x) or drop it"),
    ("cgnat-ip", r"(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?![\d.])",
     "medium", "CGNAT / Tailscale-range IP (100.64/10)",
     "drop internal overlay addresses"),
    ("tailscale-magicdns", r"\b[A-Za-z0-9-]+\.ts\.net\b", "medium",
     "Tailscale MagicDNS hostname", "use a generic hostname"),

    # ---- PII (commonly over-shared; tune/disable per project) ----
    ("email-address",
     r"\b[A-Za-z0-9._%+\-]+@(?!example\.(?:com|org|net)\b)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
     "low", "email address (possible PII)",
     "use a role/no-reply address or redact"),
]


def builtin_rules():
    """Return BUILTIN_PATTERNS as plain dicts (engine compiles them)."""
    return [
        {"id": i, "pattern": p, "severity": s, "message": m, "suggestion": g}
        for (i, p, s, m, g) in BUILTIN_PATTERNS
    ]
