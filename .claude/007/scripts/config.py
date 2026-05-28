"""007 Security Skill — Central Configuration Hub.

No external dependencies. Python 3.10+ stdlib only.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Directory structure
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
SCANNERS_DIR = BASE_DIR / "scanners"
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
PLAYBOOKS_DIR = BASE_DIR / "playbooks"

AUDIT_LOG_PATH = DATA_DIR / "audit.jsonl"
SCORE_HISTORY_PATH = DATA_DIR / "score_history.json"

# ---------------------------------------------------------------------------
# Severity levels (numeric weight for sorting)
# ---------------------------------------------------------------------------
SEVERITY: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

# ---------------------------------------------------------------------------
# Scoring weights — must sum to 1.0
# ---------------------------------------------------------------------------
SCORING_WEIGHTS: dict[str, float] = {
    "secrets": 0.20,
    "input_validation": 0.15,
    "authn_authz": 0.15,
    "data_protection": 0.15,
    "resilience": 0.10,
    "monitoring": 0.10,
    "supply_chain": 0.10,
    "compliance": 0.05,
}

SCORING_LABELS: dict[str, str] = {
    "secrets": "Secrets & Credentials",
    "input_validation": "Input Validation",
    "authn_authz": "Authentication & AuthZ",
    "data_protection": "Data Protection",
    "resilience": "Resilience",
    "monitoring": "Monitoring & Alerting",
    "supply_chain": "Supply Chain",
    "compliance": "Compliance",
}

# ---------------------------------------------------------------------------
# Verdict thresholds (descending order — first match wins)
# ---------------------------------------------------------------------------
_VERDICTS: list[tuple[int, dict]] = [
    (90, {
        "label": "Approved",
        "description": "Security posture meets production standards.",
        "emoji": "✅",
    }),
    (70, {
        "label": "Approved with caveats",
        "description": "Minor security improvements recommended before production.",
        "emoji": "⚠️",
    }),
    (50, {
        "label": "Partial block",
        "description": "Significant security issues must be resolved before deployment.",
        "emoji": "\U0001f536",
    }),
    (0, {
        "label": "Total block",
        "description": "Critical security vulnerabilities prevent deployment.",
        "emoji": "\U0001f6ab",
    }),
]

# ---------------------------------------------------------------------------
# File scanning configuration
# ---------------------------------------------------------------------------
SCANNABLE_EXTENSIONS: set[str] = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".rb", ".php", ".go", ".java", ".kt", ".swift", ".rs",
    ".sh", ".bash", ".zsh", ".fish",
    ".env", ".env.example", ".env.local", ".env.production", ".env.development",
    ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".config",
    ".json", ".xml", ".properties",
    ".tf", ".tfvars",
    ".dockerfile",
    ".pem", ".key", ".p12", ".pfx", ".crt", ".cer",
}

SKIP_DIRECTORIES: set[str] = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
    "venv", ".venv", "env",
    "dist", "build", "target", "out",
    ".idea", ".vscode",
    "vendor",
}

# ---------------------------------------------------------------------------
# Secret detection patterns: (name, compiled_regex, severity)
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("aws_access_key",
     re.compile(r"""AKIA[0-9A-Z]{16}"""),
     "CRITICAL"),
    ("aws_secret_key",
     re.compile(r"""(?i)aws.{0,20}secret.{0,20}['"` ][0-9a-zA-Z/+]{40}['"` ]"""),
     "CRITICAL"),
    ("github_token",
     re.compile(r"""gh[pousr]_[A-Za-z0-9_]{36,}"""),
     "CRITICAL"),
    ("github_classic_token",
     re.compile(r"""ghp_[A-Za-z0-9]{36}"""),
     "CRITICAL"),
    ("stripe_secret_key",
     re.compile(r"""sk_live_[0-9a-zA-Z]{24,}"""),
     "CRITICAL"),
    ("stripe_restricted_key",
     re.compile(r"""rk_live_[0-9a-zA-Z]{24,}"""),
     "CRITICAL"),
    ("twilio_token",
     re.compile(r"""SK[0-9a-f]{32}"""),
     "HIGH"),
    ("sendgrid_key",
     re.compile(r"""SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}"""),
     "HIGH"),
    ("npm_token",
     re.compile(r"""npm_[A-Za-z0-9]{36}"""),
     "HIGH"),
    ("heroku_api_key",
     re.compile(r"""(?i)heroku.{0,20}['"` ][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"` ]"""),
     "HIGH"),
    ("azure_storage_key",
     re.compile(r"""DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"""),
     "CRITICAL"),
    ("jwt_token",
     re.compile(r"""eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"""),
     "MEDIUM"),
    ("private_key_header",
     re.compile(r"""-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"""),
     "CRITICAL"),
    ("db_connection_string",
     re.compile(r"""(?i)(?:mysql|postgresql|postgres|mongodb|redis|mssql)://[^@\s]+:[^@\s]+@"""),
     "HIGH"),
    ("url_embedded_credentials",
     re.compile(r"""https?://[^:@\s/]+:[^@\s/]+@"""),
     "HIGH"),
    ("hardcoded_password",
     re.compile(r"""(?i)(?:password|passwd|pwd)\s*=\s*['"` ][^'"` ]{8,}['"` ]"""),
     "HIGH"),
    ("hardcoded_secret",
     re.compile(r"""(?i)(?:secret|api_key|apikey|access_token)\s*=\s*['"` ][^'"` ]{16,}['"` ]"""),
     "HIGH"),
    ("hardcoded_public_ip",
     re.compile(r"""(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"""),
     "LOW"),
]

# ---------------------------------------------------------------------------
# Dangerous code patterns: (name, compiled_regex, severity)
# ---------------------------------------------------------------------------
DANGEROUS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("eval_usage",
     re.compile(r"""\beval\s*\("""),
     "HIGH"),
    ("exec_usage",
     re.compile(r"""\bexec\s*\("""),
     "HIGH"),
    ("subprocess_shell_true",
     re.compile(r"""subprocess\.[a-z_]+\([^)]*shell\s*=\s*True"""),
     "HIGH"),
    ("os_system",
     re.compile(r"""\bos\.system\s*\("""),
     "MEDIUM"),
    ("pickle_load",
     re.compile(r"""\bpickle\.loads?\s*\("""),
     "HIGH"),
    ("yaml_unsafe_load",
     re.compile(r"""\byaml\.load\s*\([^,)]+\)"""),
     "HIGH"),
    ("sql_string_format",
     re.compile(r"""(?i)(?:execute|query)\s*\(\s*[f"'].*%[sd]"""),
     "HIGH"),
    ("sql_concatenation",
     re.compile(r"""(?i)(?:SELECT|INSERT|UPDATE|DELETE)\s+['"]\s*\+"""),
     "HIGH"),
]

# ---------------------------------------------------------------------------
# Operational limits
# ---------------------------------------------------------------------------
LIMITS: dict[str, int] = {
    "max_file_size_bytes": 5 * 1024 * 1024,   # 5 MB
    "max_files_per_scan": 10_000,
    "file_read_timeout_seconds": 10,
    "full_scan_timeout_seconds": 300,
    "max_findings_per_file": 50,
    "max_report_findings": 1_000,
}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def ensure_directories() -> None:
    """Create required runtime directories if they do not exist."""
    for d in (DATA_DIR, REPORTS_DIR, PLAYBOOKS_DIR):
        d.mkdir(parents=True, exist_ok=True)


def get_timestamp() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def setup_logging(name: str, level: int = logging.INFO) -> logging.Logger:
    """Create and return a named logger with a console handler."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(name)s] %(levelname)s %(message)s")
        )
        logger.addHandler(handler)
    logger.setLevel(level)
    return logger


def log_audit_event(
    action: str,
    target: str,
    result: str,
    details: dict | None = None,
) -> None:
    """Append a JSON Lines audit event to the audit log."""
    ensure_directories()
    entry = {
        "timestamp": get_timestamp(),
        "action": action,
        "target": target,
        "result": result,
        "details": details or {},
    }
    with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def get_verdict(score: float) -> dict:
    """Map a numeric score (0-100) to a verdict dict."""
    for threshold, verdict in _VERDICTS:
        if score >= threshold:
            return verdict
    return _VERDICTS[-1][1]


def calculate_weighted_score(domain_scores: dict[str, float]) -> float:
    """Compute the weighted final score from per-domain scores."""
    total = 0.0
    for domain, weight in SCORING_WEIGHTS.items():
        total += domain_scores.get(domain, 0.0) * weight
    return round(total, 2)


if __name__ == "__main__":
    print("007 config loaded OK")
    print(f"  Scoring weights sum: {sum(SCORING_WEIGHTS.values()):.2f}")
    print(f"  Secret patterns:     {len(SECRET_PATTERNS)}")
    print(f"  Dangerous patterns:  {len(DANGEROUS_PATTERNS)}")
    ensure_directories()
    print(f"  Data dir:            {DATA_DIR}")
