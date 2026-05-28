"""007 Score Calculator -- Unified security scoring engine.

Aggregates results from all scanners into a weighted per-domain security
score covering 8 domains. Saves score history for trend analysis.

Usage:
    python score_calculator.py --target /path/to/project
    python score_calculator.py --target /path/to/project --output json --verbose
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import (
    BASE_DIR,
    DATA_DIR,
    SCORING_WEIGHTS,
    SCORING_LABELS,
    SCORE_HISTORY_PATH,
    SEVERITY,
    SCANNABLE_EXTENSIONS,
    SKIP_DIRECTORIES,
    LIMITS,
    ensure_directories,
    get_verdict,
    get_timestamp,
    log_audit_event,
    setup_logging,
    calculate_weighted_score,
)

sys.path.insert(0, str(Path(__file__).resolve().parent / "scanners"))

import secrets_scanner
import dependency_scanner
import injection_scanner
import quick_scan

logger = setup_logging("007-score-calculator")

_SENSITIVE_FINDING_KEYS = {
    "snippet", "secret", "token", "password", "access_token",
    "app_secret", "authorization_code", "client_secret",
}

# Positive-signal patterns for domain scoring
_AUTH_PATTERNS = [
    re.compile(r"""(?i)(?:@login_required|@auth|@require_auth|@authenticated|@permission_required)"""),
    re.compile(r"""(?i)(?:passport\.authenticate|isAuthenticated|requireAuth|authMiddleware)"""),
    re.compile(r"""(?i)(?:jwt\.verify|jwt\.decode|verify_jwt|decode_token)"""),
    re.compile(r"""(?i)(?:OAuth|oauth2|OpenID|openid)"""),
    re.compile(r"""(?i)(?:bcrypt|argon2|pbkdf2|scrypt)"""),
    re.compile(r"""(?i)(?:RBAC|role_required|has_permission|check_permission)"""),
]
_ENCRYPTION_PATTERNS = [
    re.compile(r"""(?i)(?:from\s+cryptography|import\s+cryptography)"""),
    re.compile(r"""(?i)(?:from\s+hashlib|import\s+hashlib)"""),
    re.compile(r"""(?i)(?:AES|Fernet|RSA|ECDSA|ChaCha20)"""),
    re.compile(r"""(?i)(?:https://|TLS|ssl_context|ssl\.create_default_context)"""),
    re.compile(r"""(?i)verify\s*=\s*True"""),
    re.compile(r"""(?i)(?:encrypt|decrypt|sign|verify_signature)"""),
]
_RESILIENCE_PATTERNS = [
    re.compile(r"""(?:try\s*:|except\s+)"""),
    re.compile(r"""(?i)(?:timeout|connect_timeout|read_timeout)"""),
    re.compile(r"""(?i)(?:retry|retries|backoff|exponential_backoff|tenacity)"""),
    re.compile(r"""(?i)(?:circuit_breaker|CircuitBreaker|pybreaker)"""),
    re.compile(r"""(?i)(?:rate_limit|ratelimit|throttle|RateLimiter)"""),
    re.compile(r"""(?i)(?:graceful_shutdown|signal\.signal|atexit)"""),
]
_MONITORING_PATTERNS = [
    re.compile(r"""(?:import\s+logging|from\s+logging)"""),
    re.compile(r"""(?i)(?:logger\.\w+|logging\.getLogger)"""),
    re.compile(r"""(?i)(?:sentry|sentry_sdk)"""),
    re.compile(r"""(?i)(?:prometheus|grafana|datadog|newrelic)"""),
    re.compile(r"""(?i)(?:audit_log|audit_trail|log_event|log_action)"""),
    re.compile(r"""(?i)(?:structlog|loguru)"""),
]
_INPUT_VALIDATION_PATTERNS = [
    re.compile(r"""(?i)(?:pydantic|BaseModel|validator|field_validator)"""),
    re.compile(r"""(?i)(?:jsonschema|validate|Schema|Marshmallow)"""),
    re.compile(r"""(?i)(?:sanitize|escape|bleach|html\.escape|markupsafe)"""),
    re.compile(r"""(?i)(?:parameterized|placeholder)"""),
    re.compile(r"""(?i)(?:zod|yup|joi|express-validator)"""),
]


def _collect_source_files(target: Path) -> list[Path]:
    files: list[Path] = []
    max_files = LIMITS["max_files_per_scan"]
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]
        for fname in filenames:
            if len(files) >= max_files:
                return files
            fpath = Path(root) / fname
            name = fpath.name.lower()
            for ext in SCANNABLE_EXTENSIONS:
                if name.endswith(ext) or fpath.suffix.lower() == ext:
                    files.append(fpath)
                    break
    return files


def _count_pattern_matches(files: list[Path], patterns: list[re.Pattern]) -> int:
    count = 0
    for fpath in files:
        try:
            if fpath.stat().st_size > LIMITS["max_file_size_bytes"]:
                continue
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pat in patterns:
            if pat.search(text):
                count += 1
                break
    return count


def _deduplicate_findings(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    unique: list[dict] = []
    for f in findings:
        key = (f.get("file", ""), f.get("line", 0), f.get("pattern", ""))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _score_from_findings(findings: list[dict], max_deduction: int = 100) -> int:
    deductions = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 3, "LOW": 1, "INFO": 0}
    total = sum(deductions.get(f.get("severity", "INFO"), 0) for f in findings)
    return max(0, min(100, max_deduction - total))


def _score_from_positive_signals(match_count: int, total_files: int,
                                  base_score: int = 30, max_score: int = 100) -> int:
    if total_files == 0:
        return base_score
    ratio = min(1.0, match_count / max(1, total_files * 0.1))
    return min(max_score, int(base_score + ratio * (max_score - base_score)))


def compute_domain_scores(secrets_findings, injection_findings, dependency_report,
                           quick_findings, source_files, total_source_files) -> dict[str, float]:
    scores: dict[str, float] = {}

    # secrets
    secret_only = [f for f in secrets_findings if f.get("type") == "secret"]
    scores["secrets"] = float(_score_from_findings(secret_only))

    # input_validation
    inj_input = [f for f in injection_findings
                 if f.get("injection_type") in ("sql_injection", "code_injection",
                                                 "command_injection", "xss", "path_traversal")]
    neg = _score_from_findings(inj_input)
    pos = _score_from_positive_signals(_count_pattern_matches(source_files, _INPUT_VALIDATION_PATTERNS), total_source_files)
    scores["input_validation"] = float(min(100, (neg + pos) // 2))

    # authn_authz
    auth_count = _count_pattern_matches(source_files, _AUTH_PATTERNS)
    if total_source_files == 0:
        scores["authn_authz"] = 50.0
    elif auth_count == 0:
        scores["authn_authz"] = 25.0
    else:
        scores["authn_authz"] = float(_score_from_positive_signals(auth_count, total_source_files, 40, 95))

    # data_protection
    enc_count = _count_pattern_matches(source_files, _ENCRYPTION_PATTERNS)
    data_exp = [f for f in secrets_findings
                if f.get("pattern") in ("db_connection_string", "url_embedded_credentials", "hardcoded_public_ip")]
    neg_dp = _score_from_findings(data_exp)
    pos_dp = _score_from_positive_signals(enc_count, total_source_files)
    scores["data_protection"] = float(min(100, (neg_dp + pos_dp) // 2))

    # resilience
    res_count = _count_pattern_matches(source_files, _RESILIENCE_PATTERNS)
    scores["resilience"] = float(_score_from_positive_signals(res_count, total_source_files, 30, 95))

    # monitoring
    mon_count = _count_pattern_matches(source_files, _MONITORING_PATTERNS)
    scores["monitoring"] = float(_score_from_positive_signals(mon_count, total_source_files, 20, 95))

    # supply_chain
    scores["supply_chain"] = float(max(0, min(100, dependency_report.get("score", 50))))

    # compliance (average of other domains)
    other = [scores.get(k, 0.0) for k in SCORING_WEIGHTS if k != "compliance"]
    scores["compliance"] = float(round(sum(other) / len(other), 2)) if other else 50.0

    return scores


def _save_score_history(target, domain_scores, final_score, verdict) -> None:
    ensure_directories()
    entry = {
        "timestamp": get_timestamp(),
        "target": target,
        "domain_scores": domain_scores,
        "final_score": final_score,
        "verdict": {"label": verdict["label"], "description": verdict["description"], "emoji": verdict["emoji"]},
    }
    history: list[dict] = []
    if SCORE_HISTORY_PATH.exists():
        try:
            raw = SCORE_HISTORY_PATH.read_text(encoding="utf-8")
            if raw.strip():
                parsed = json.loads(raw)
                history = parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, OSError):
            history = []
    history.append(entry)
    SCORE_HISTORY_PATH.write_text(json.dumps(history, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _bar(score: float, width: int = 20) -> str:
    filled = int(score / 100 * width)
    return "[" + "#" * filled + "." * (width - filled) + "]"


def _redact_findings(findings: list[dict]) -> list[dict]:
    redacted = []
    for f in findings:
        safe = {}
        ftype = str(f.get("type", "")).lower()
        for key, value in f.items():
            if key.lower() in _SENSITIVE_FINDING_KEYS:
                safe[key] = "[redacted]"
            elif ftype == "secret" and key.lower() in {"entropy", "match", "raw", "value"}:
                safe[key] = "[redacted]"
            else:
                safe[key] = value
        redacted.append(safe)
    return redacted


def format_text_report(target, domain_scores, final_score, verdict,
                        scanner_summaries, total_findings, elapsed):
    lines = []
    lines.append("=" * 72)
    lines.append("  007 SECURITY SCORE REPORT")
    lines.append("=" * 72)
    lines.append(f"  Target:          {target}")
    lines.append(f"  Timestamp:       {get_timestamp()}")
    lines.append(f"  Duration:        {elapsed:.2f}s")
    lines.append(f"  Total findings:  {total_findings} (deduplicated)")
    lines.append("")
    lines.append("-" * 72)
    lines.append("  SCANNER RESULTS")
    lines.append("-" * 72)
    for name, summary in scanner_summaries.items():
        lines.append(f"    {name:<25} findings={summary.get('findings', 0):<6} score={summary.get('score', 'N/A')}")
    lines.append("")
    lines.append("-" * 72)
    lines.append("  DOMAIN SCORES")
    lines.append("-" * 72)
    lines.append(f"    {'Domain':<30} {'Weight':>6}  {'Score':>5}  Bar")
    lines.append(f"    {'-'*30} {'-'*6}  {'-'*5}  {'-'*22}")
    for domain, weight in SCORING_WEIGHTS.items():
        score = domain_scores.get(domain, 0.0)
        label = SCORING_LABELS.get(domain, domain)
        lines.append(f"    {label:<30} {weight*100:.0f}%{'':<4}  {score:>5.1f}  {_bar(score)}")
    lines.append("")
    lines.append("=" * 72)
    lines.append(f"  FINAL SCORE:  {final_score:.1f} / 100")
    lines.append(f"  VERDICT:      {verdict['emoji']} {verdict['label']}")
    lines.append(f"                {verdict['description']}")
    lines.append("=" * 72)
    lines.append("")
    return "\n".join(lines)


def build_json_report(target, domain_scores, final_score, verdict,
                       scanner_summaries, all_findings, total_findings, elapsed):
    return {
        "report": "score_calculator", "target": target, "timestamp": get_timestamp(),
        "duration_seconds": round(elapsed, 3), "total_findings": total_findings,
        "domain_scores": domain_scores, "final_score": final_score,
        "verdict": {"label": verdict["label"], "description": verdict["description"], "emoji": verdict["emoji"]},
        "scanner_summaries": scanner_summaries,
        "findings": _redact_findings(all_findings),
    }


def run_score(target_path: str, output_format: str = "text", verbose: bool = False) -> dict:
    if verbose:
        logger.setLevel("DEBUG")
    ensure_directories()
    target = Path(target_path).resolve()
    if not target.exists() or not target.is_dir():
        logger.error("Target does not exist or is not a directory: %s", target)
        sys.exit(1)

    logger.info("Starting unified security score calculation for %s", target)
    start_time = time.time()
    target_str = str(target)
    scanner_summaries: dict[str, dict] = {}

    def _safe_scan(scanner_module, **kwargs):
        try:
            return scanner_module.run_scan(**kwargs)
        except SystemExit:
            return {"findings": [], "score": 50, "total_findings": 0}

    logger.info("Running secrets scanner...")
    secrets_report = _safe_scan(secrets_scanner, target_path=target_str, output_format="json", verbose=verbose)
    secrets_findings = secrets_report.get("findings", [])
    scanner_summaries["secrets_scanner"] = {"findings": len(secrets_findings), "score": secrets_report.get("score", 50)}

    logger.info("Running dependency scanner...")
    dep_report = _safe_scan(dependency_scanner, target_path=target_str, output_format="json", verbose=verbose)
    dep_findings = dep_report.get("findings", [])
    scanner_summaries["dependency_scanner"] = {"findings": len(dep_findings), "score": dep_report.get("score", 50)}

    logger.info("Running injection scanner...")
    inj_report = _safe_scan(injection_scanner, target_path=target_str, output_format="json", verbose=verbose)
    inj_findings = inj_report.get("findings", [])
    scanner_summaries["injection_scanner"] = {"findings": len(inj_findings), "score": inj_report.get("score", 50)}

    logger.info("Running quick scan...")
    quick_report = _safe_scan(quick_scan, target_path=target_str, output_format="json", verbose=verbose)
    quick_findings = quick_report.get("findings", [])
    scanner_summaries["quick_scan"] = {"findings": len(quick_findings), "score": quick_report.get("score", 50)}

    all_raw = secrets_findings + dep_findings + inj_findings + quick_findings
    all_findings = _deduplicate_findings(all_raw)
    total_findings = len(all_findings)
    logger.info("Aggregated %d raw -> %d unique findings", len(all_raw), total_findings)

    source_files = _collect_source_files(target)
    total_source_files = len(source_files)

    domain_scores = compute_domain_scores(
        secrets_findings=secrets_findings, injection_findings=inj_findings,
        dependency_report=dep_report, quick_findings=quick_findings,
        source_files=source_files, total_source_files=total_source_files,
    )

    final_score = calculate_weighted_score(domain_scores)
    verdict = get_verdict(final_score)
    elapsed = time.time() - start_time

    logger.info("Score calculation complete in %.2fs: final_score=%.1f, verdict=%s",
                elapsed, final_score, verdict["label"])

    _save_score_history(target_str, domain_scores, final_score, verdict)
    log_audit_event("score_calculation", target_str,
        f"final_score={final_score}, verdict={verdict['label']}",
        {"domain_scores": domain_scores, "total_findings": total_findings,
         "scanner_summaries": scanner_summaries, "duration_seconds": round(elapsed, 3)})

    report = build_json_report(target_str, domain_scores, final_score, verdict,
                                scanner_summaries, all_findings, total_findings, elapsed)

    if output_format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_text_report(target_str, domain_scores, final_score, verdict,
                                  scanner_summaries, total_findings, elapsed))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="007 Score Calculator -- Unified security scoring engine.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--verbose", action="store_true", default=False)
    args = parser.parse_args()
    run_score(target_path=args.target, output_format=args.output, verbose=args.verbose)
