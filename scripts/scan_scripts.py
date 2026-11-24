# cat > scan_secrets.py << 'EOF'
#!/usr/bin/env python3
"""
Scan the lines ADDED between two commits for hardcoded secrets.
Usage: python scan_secrets.py <base_sha> <head_sha>
Exit code 0 = clean, 1 = secrets found.
"""
import math
import re
import subprocess
import sys
from collections import Counter

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's empty tree

# Known provider formats (high confidence)
RULES = [
    ("AWS access key ID",     r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("GitHub token",          r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ("Slack token",           r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    ("Slack webhook",         r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    ("Stripe live key",       r"\b(sk|rk)_live_[0-9a-zA-Z]{24,}\b"),
    ("Google API key",        r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("OpenAI key",            r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}\b"),
    ("Anthropic key",         r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b"),
    ("SendGrid key",          r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("npm token",             r"\bnpm_[A-Za-z0-9]{36}\b"),
    ("Private key block",     r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
    ("JWT",                   r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    ("Password in URL",       r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:[^\s@/]+@[^\s/]+"),
    # Twilio
    ("Twilio API Key SID",          r"\bSK[0-9a-fA-F]{32}\b"),
    ("Twilio Account SID",          r"\bAC[0-9a-fA-F]{32}\b"),
    ("Twilio auth token",           r"(?i)twilio[\w\-\s]{0,20}token[\"'\s:=]+[0-9a-f]{32}\b"),

    # Cloudflare
    ("Cloudflare API token (new)",  r"\bcfut_[A-Za-z0-9_\-]{40,}\b"),
    ("Cloudflare API token",        r"(?i)cloudflare[\w\-\s]{0,20}token[\"'\s:=]+[A-Za-z0-9_\-]{40}\b"),
    ("Cloudflare Global API key",   r"(?i)cloudflare[\w\-\s]{0,20}key[\"'\s:=]+[0-9a-f]{37}\b"),

    # WhatsApp / Meta
    ("WhatsApp/Meta access token",  r"\bEAA[A-Za-z0-9]{60,}\b"),
    ("Meta app secret",             r"(?i)(whatsapp|meta|facebook)[\w\-\s]{0,20}secret[\"'\s:=]+[0-9a-f]{32}\b"),

    # Google
    ("Google OAuth client secret",  r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b"),
    ("Gmail app password",          r"(?i)(gmail|google|smtp)[\w\-\s]{0,20}(password|passwd|pwd)[\"'\s:=]+[a-z]{4}\s?[a-z]{4}\s?[a-z]{4}\s?[a-z]{4}\b"),
    ("Google/Gmail password",       r"(?i)(gmail|google|mail)[\w\-\s]{0,20}(password|passwd|pwd)[\"'\s:=]+[^\s'\",;]{8,}"),
]

# Generic: a key-like variable name assigned a long string (checked with entropy)
GENERIC = re.compile(
    r"""(?i)([a-z0-9_.-]*(api[_-]?key|secret|token|passw(or)?d|credential|auth)[a-z0-9_.-]*)"""
    r"""\s*[:=]\s*['"]?([^\s'",;]{16,})"""
)
PLACEHOLDER = re.compile(r"(?i)(example|changeme|your[_-]|xxxx|<|\$\{|process\.env|os\.environ|getenv|placeholder|dummy)")
IGNORE_MARKER = "secret-scan:ignore"
SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".woff", ".woff2",
            ".lock", ".min.js", ".map")


def entropy(s):
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def added_lines(base, head):
    """Yield (file, line_number, text) for every line added in base..head."""
    if set(base) == {"0"}:          # brand-new branch: scan everything
        base = EMPTY_TREE
    diff = subprocess.run(
        ["git", "diff", "-U0", "--no-color", base, head],
        capture_output=True, text=True, check=True,
    ).stdout
    path, line_no = None, 0
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            path = raw[6:]
        elif raw.startswith("@@"):
            # @@ -a,b +c,d @@  -> new file starts at line c
            new_part = raw.split("+", 1)[1].split(" ", 1)[0]
            line_no = int(new_part.split(",")[0])
        elif raw.startswith("+") and not raw.startswith("+++"):
            if path and not path.lower().endswith(SKIP_EXT):
                yield path, line_no, raw[1:]
            line_no += 1


def redact(text):
    return text[:4] + "****" if len(text) > 8 else "****"


def scan(base, head):
    findings = []
    for path, line_no, text in added_lines(base, head):
        if IGNORE_MARKER in text:
            continue
        for name, pattern in RULES:
            m = re.search(pattern, text)
            if m:
                findings.append((path, line_no, name, redact(m.group(0))))
        for m in GENERIC.finditer(text):
            value = m.group(4)
            if PLACEHOLDER.search(value):
                continue
            if entropy(value) >= 3.5:  # random-looking = likely a real key
                findings.append((path, line_no, f"Hardcoded {m.group(1)}", redact(value)))
    return findings


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python scan_secrets.py <base_sha> <head_sha>")
        sys.exit(2)
    results = scan(sys.argv[1], sys.argv[2])
    if results:
        print(f"FOUND {len(results)} possible secret(s):\n")
        for path, line_no, name, shown in results:
            print(f"  {path}:{line_no}  {name}  ({shown})")
        print("\nRemove the secret, rotate it, and use environment variables or a secrets manager.")
        print("If it is a false positive, add  secret-scan:ignore  as a comment on that line.")
        sys.exit(1)
    print("No secrets found in this push.")
