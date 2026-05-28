"""007 Secrets Scanner -- Deep secret detection with entropy analysis.

Scans for hardcoded secrets, API keys, tokens, and high-entropy values
across project files. Includes Shannon entropy analysis, base64 detection,
and context-aware false positive reduction.

Usage:
    python secrets_scanner.py --target /path/to/project
    python secrets_scanner.py --target /path/to/project --output json --verbose
"""

import argparse
import base64
import json
import math
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    SCANNABLE_EXTENSIONS,
    SKIP_DIRECTORIES,
    SECRET_PATTERNS,
    LIMITS,
    SEVERITY,
    ensure_directories,
    get_verdict,
    get_timestamp,
    log_audit_event,
    setup_logging,
)

logger = setup_logging("007-secrets-scanner")

# Extra extensions targeted specifically by this scanner
_EXTRA_SENSITIVE_EXTENSIONS: set[str] = {
    ".env", ".env.example", ".env.local", ".env.production",
    ".env.development", ".env.staging", ".env.test",
    ".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".jks",
    ".pkcs12", ".p8", ".ppk",
}

SCAN_EXTENSIONS: set[str] = SCANNABLE_EXTENSIONS | _EXTRA_SENSITIVE_EXTENSIONS

SENSITIVE_FILE_NAMES: set[str] = {
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
    "id_rsa.pub", "id_ed25519.pub",
    ".htpasswd", ".netrc", "credentials", "secrets",
}

# Entropy thresholds
_ENTROPY_THRESHOLD = 4.0
_HIGH_ENTROPY_THRESHOLD = 5.0
_MIN_SECRET_LEN = 16

_PRIVATE_IP_RE = re.compile(
    r"""^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|localhost|::1)"""
)

_PLACEHOLDER_RE = re.compile(
    r"""(?i)(?:example|sample|dummy|fake|test|your[-_]?(?:key|token|secret)|xxx+|placeholder|changeme|<[^>]+>|\$\{[^}]+\})"""
)

_ASSIGN_RE = re.compile(
    r"""(?:=|:)\s*['"` ]([A-Za-z0-9+/\-_]{20,})['"` ]"""
)

SCORE_DEDUCTIONS: dict[str, int] = {
    "CRITICAL": 15,
    "HIGH": 8,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0,
}


# ---------------------------------------------------------------------------
# Entropy helpers
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy of a string."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def is_high_entropy_secret(value: str) -> bool:
    """Return True if value is long enough and has entropy above threshold."""
    if len(value) < _MIN_SECRET_LEN:
        return False
    clean = value.strip("'\"` ")
    if _PLACEHOLDER_RE.search(clean):
        return False
    return shannon_entropy(clean) >= _HIGH_ENTROPY_THRESHOLD


def is_base64_high_entropy(value: str) -> bool:
    """Return True if value is base64 with high decoded entropy."""
    if len(value) < _MIN_SECRET_LEN:
        return False
    if not re.fullmatch(r"""[A-Za-z0-9+/=]+""", value):
        return False
    if shannon_entropy(value) < _ENTROPY_THRESHOLD:
        return False
    try:
        decoded = base64.b64decode(value + "==").decode("utf-8", errors="replace")
        return shannon_entropy(decoded) >= _HIGH_ENTROPY_THRESHOLD
    except Exception:
        return False


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def is_test_file(filepath: Path) -> bool:
    """Return True if the file is in a test directory or has a test name."""
    parts = {p.lower() for p in filepath.parts}
    if parts & {"test", "tests", "spec", "specs", "__tests__", "testing"}:
        return True
    name = filepath.name.lower()
    return (
        name.startswith("test_")
        or name.endswith("_test.py")
        or ".test." in name
        or ".spec." in name
    )


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRECTORIES


def _is_target_file(path: Path) -> bool:
    name = path.name.lower()
    if name in SENSITIVE_FILE_NAMES:
        return True
    for ext in SCAN_EXTENSIONS:
        if name.endswith(ext):
            return True
    return path.suffix.lower() in SCAN_EXTENSIONS


def collect_files(target: Path) -> list[Path]:
    """Walk target directory and return scannable file paths."""
    files: list[Path] = []
    max_files = LIMITS["max_files_per_scan"]

    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if not _should_skip_dir(d)]
        for fname in filenames:
            if len(files) >= max_files:
                return files
            fpath = Path(root) / fname
            if _is_target_file(fpath):
                files.append(fpath)

    return files


def _is_comment(line: str, ext: str) -> bool:
    """Heuristic: return True if line is a comment."""
    stripped = line.strip()
    if ext in (".py", ".rb", ".sh", ".bash", ".yaml", ".yml", ".toml"):
        return stripped.startswith("#")
    if ext in (".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".swift", ".kt", ".c", ".cpp"):
        return stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*")
    return False


def _in_md_code_block(line: str) -> bool:
    return line.strip().startswith("```")


# ---------------------------------------------------------------------------
# Core scanning logic
# ---------------------------------------------------------------------------

def scan_file(filepath: Path, verbose: bool = False) -> list[dict]:
    """Scan a single file and return a list of secret findings."""
    findings: list[dict] = []
    file_str = str(filepath)
    ext = filepath.suffix.lower()
    test_file = is_test_file(filepath)
    in_code_block = False

    try:
        size = filepath.stat().st_size
        if size > LIMITS["max_file_size_bytes"]:
            return findings
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        if verbose:
            logger.debug("Cannot read %s: %s", filepath, exc)
        return findings

    # Flag raw private key files before scanning content
    if filepath.suffix.lower() in (".pem", ".key", ".p12", ".pfx", ".jks") or filepath.name in SENSITIVE_FILE_NAMES:
        if "PRIVATE KEY" in text or len(text.strip()) > 0:
            findings.append({
                "type": "secret",
                "pattern": "private_key_file",
                "severity": "CRITICAL" if not test_file else "HIGH",
                "file": file_str,
                "line": 0,
                "snippet": f"Sensitive key file: {filepath.name}",
            })

    lines = text.splitlines()

    for line_num, line in enumerate(lines, start=1):
        if len(findings) >= LIMITS["max_findings_per_file"]:
            break

        # Track markdown code blocks
        if ext in (".md", ".rst", ".txt"):
            if _in_md_code_block(line):
                in_code_block = not in_code_block
                continue
            if in_code_block:
                continue

        if _is_comment(line, ext):
            continue

        # --- Pattern matching ---
        for pattern_name, regex, base_severity in SECRET_PATTERNS:
            m = regex.search(line)
            if not m:
                continue

            matched = m.group(0)

            # Skip private IPs for the IP pattern
            if pattern_name == "hardcoded_public_ip" and _PRIVATE_IP_RE.match(matched):
                continue

            # Skip placeholders
            if _PLACEHOLDER_RE.search(matched):
                continue

            # Downgrade severity for test files
            severity = base_severity
            if test_file:
                if severity == "CRITICAL":
                    severity = "HIGH"
                elif severity == "HIGH":
                    severity = "MEDIUM"

            findings.append({
                "type": "secret",
                "pattern": pattern_name,
                "severity": severity,
                "file": file_str,
                "line": line_num,
                "snippet": f"{line.strip()[:70]}...",
            })

        # --- Entropy analysis for assignment-like patterns ---
        assign_match = _ASSIGN_RE.search(line)
        if assign_match:
            candidate = assign_match.group(1)
            if is_high_entropy_secret(candidate) or is_base64_high_entropy(candidate):
                already = any(f["line"] == line_num and f["type"] == "secret" for f in findings)
                if not already:
                    findings.append({
                        "type": "secret",
                        "pattern": "high_entropy_value",
                        "severity": "HIGH" if not test_file else "MEDIUM",
                        "file": file_str,
                        "line": line_num,
                        "snippet": f"{line.strip()[:70]}...",
                    })

    return findings


# ---------------------------------------------------------------------------
# Aggregation & scoring
# ---------------------------------------------------------------------------

def compute_score(findings: list[dict]) -> int:
    """Compute secrets score starting at 100, deducting by severity."""
    score = 100
    for f in findings:
        score -= SCORE_DEDUCTIONS.get(f.get("severity", "INFO"), 0)
    return max(0, score)


def aggregate_by_severity(findings: list[dict]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts


def aggregate_by_file(findings: list[dict]) -> dict[str, list[dict]]:
    by_file: dict[str, list[dict]] = {}
    for f in findings:
        by_file.setdefault(f["file"], []).append(f)
    return by_file


# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------

def format_text_report(
    target: str,
    total_files: int,
    findings: list[dict],
    severity_counts: dict[str, int],
    score: int,
    verdict: dict,
    elapsed: float,
) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("  007 SECRETS SCANNER REPORT")
    lines.append("=" * 70)
    lines.append(f"  Target:         {target}")
    lines.append(f"  Timestamp:      {get_timestamp()}")
    lines.append(f"  Duration:       {elapsed:.2f}s")
    lines.append(f"  Files scanned:  {total_files}")
    lines.append(f"  Total findings: {len(findings)}")
    lines.append("")

    lines.append("-" * 70)
    lines.append("  FINDINGS BY SEVERITY")
    lines.append("-" * 70)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = severity_counts.get(sev, 0)
        bar = "#" * min(count, 40)
        lines.append(f"    {sev:<10} {count:>5}  {bar}")
    lines.append("")

    by_file = aggregate_by_file(findings)
    high_plus = [f for f in findings if SEVERITY.get(f.get("severity", "INFO"), 0) >= SEVERITY["HIGH"]]

    if high_plus:
        lines.append("-" * 70)
        lines.append("  CRITICAL & HIGH FINDINGS")
        lines.append("-" * 70)
        for fpath, file_findings in sorted(by_file.items()):
            filtered = [f for f in file_findings if SEVERITY.get(f.get("severity", "INFO"), 0) >= SEVERITY["HIGH"]]
            if not filtered:
                continue
            lines.append(f"  {fpath}")
            for f in sorted(filtered, key=lambda x: x.get("line", 0)):
                lines.append(f"    L{f['line']:>5}  [{f['severity']:<8}] {f['pattern']}")
        lines.append("")
    else:
        lines.append("  No CRITICAL or HIGH findings.")
        lines.append("")

    lines.append("=" * 70)
    lines.append(f"  SECRETS SCORE:  {score} / 100")
    lines.append(f"  VERDICT:        {verdict['emoji']} {verdict['label']}")
    lines.append(f"                  {verdict['description']}")
    lines.append("=" * 70)
    lines.append("")
    return "\n".join(lines)


def build_json_report(
    target: str,
    total_files: int,
    findings: list[dict],
    severity_counts: dict[str, int],
    score: int,
    verdict: dict,
    elapsed: float,
) -> dict:
    return {
        "scan": "secrets_scanner",
        "target": target,
        "timestamp": get_timestamp(),
        "duration_seconds": round(elapsed, 3),
        "total_files_scanned": total_files,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "score": score,
        "verdict": {
            "label": verdict["label"],
            "description": verdict["description"],
            "emoji": verdict["emoji"],
        },
        "findings": findings,
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_scan(
    target_path: str,
    output_format: str = "text",
    verbose: bool = False,
) -> dict:
    """Execute the secrets scan and return the report dict."""
    if verbose:
        logger.setLevel("DEBUG")

    ensure_directories()
    target = Path(target_path).resolve()

    if not target.exists() or not target.is_dir():
        logger.error("Target path does not exist or is not a directory: %s", target)
        sys.exit(1)

    logger.info("Starting secrets scan of %s", target)
    start_time = time.time()

    files = collect_files(target)
    total_files = len(files)
    logger.info("Collected %d files for secrets scanning", total_files)

    all_findings: list[dict] = []
    max_report = LIMITS["max_report_findings"]

    for fpath in files:
        if len(all_findings) >= max_report:
            logger.warning("Reached max_report_findings limit. Truncating.")
            break
        file_findings = scan_file(fpath, verbose=verbose)
        remaining = max_report - len(all_findings)
        all_findings.extend(file_findings[:remaining])

    elapsed = time.time() - start_time
    severity_counts = aggregate_by_severity(all_findings)
    score = compute_score(all_findings)
    verdict = get_verdict(score)

    logger.info(
        "Secrets scan complete: %d files, %d findings, score=%d in %.2fs",
        total_files, len(all_findings), score, elapsed,
    )

    log_audit_event(
        action="secrets_scan",
        target=str(target),
        result=f"score={score}, findings={len(all_findings)}, verdict={verdict['label']}",
        details={
            "total_files": total_files,
            "severity_counts": severity_counts,
            "duration_seconds": round(elapsed, 3),
        },
    )

    report = build_json_report(
        str(target), total_files, all_findings, severity_counts, score, verdict, elapsed,
    )

    if output_format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_text_report(
            str(target), total_files, all_findings, severity_counts, score, verdict, elapsed,
        ))

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="007 Secrets Scanner -- Deep secret detection with entropy analysis.",
        epilog="Example: python secrets_scanner.py --target ./my-project --output json",
    )
    parser.add_argument("--target", required=True, help="Path to the directory to scan.")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--verbose", action="store_true", default=False)
    args = parser.parse_args()
    run_scan(target_path=args.target, output_format=args.output, verbose=args.verbose)
