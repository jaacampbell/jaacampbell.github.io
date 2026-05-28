"""007 Quick Scan -- Fast automated security scan of a target directory.

Recursively scans files for secret patterns, dangerous code constructs,
permission issues, and oversized files. Produces a scored summary report.

Usage:
    python quick_scan.py --target /path/to/project
    python quick_scan.py --target /path/to/project --output json --verbose
"""

import argparse
import json
import os
import stat
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config import (
    SCANNABLE_EXTENSIONS,
    SKIP_DIRECTORIES,
    SECRET_PATTERNS,
    DANGEROUS_PATTERNS,
    LIMITS,
    SEVERITY,
    ensure_directories,
    get_verdict,
    get_timestamp,
    log_audit_event,
    setup_logging,
)

SCORE_DEDUCTIONS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
REDACT_KEEP_CHARS = 6


def _redact(text: str) -> str:
    text = text.strip()
    return text if len(text) <= REDACT_KEEP_CHARS else text[:REDACT_KEEP_CHARS] + "****"


def _snippet(line: str, match_start: int, context: int = 40) -> str:
    start = max(0, match_start - context // 2)
    end = min(len(line), match_start + context)
    return _redact(line[start:end].strip())


def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRECTORIES


def _is_scannable(path: Path) -> bool:
    name = path.name.lower()
    for ext in SCANNABLE_EXTENSIONS:
        if name.endswith(ext):
            return True
    return path.suffix.lower() in SCANNABLE_EXTENSIONS


def _check_permissions(filepath: Path) -> dict | None:
    if sys.platform == "win32":
        return None
    try:
        mode = filepath.stat().st_mode
        perms = stat.S_IMODE(mode)
        if perms & 0o777 == 0o777:
            return {"type": "permission", "pattern": "world_rwx_0777", "severity": "HIGH",
                    "file": str(filepath), "line": 0, "snippet": f"mode={oct(perms)}"}
        if perms & 0o666 == 0o666:
            return {"type": "permission", "pattern": "world_rw_0666", "severity": "MEDIUM",
                    "file": str(filepath), "line": 0, "snippet": f"mode={oct(perms)}"}
    except OSError:
        pass
    return None


def collect_files(target: Path, logger) -> list[Path]:
    files: list[Path] = []
    max_files = LIMITS["max_files_per_scan"]
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if not _should_skip_dir(d)]
        for fname in filenames:
            if len(files) >= max_files:
                logger.warning("Reached max_files_per_scan limit (%d). Stopping.", max_files)
                return files
            fpath = Path(root) / fname
            if _is_scannable(fpath):
                files.append(fpath)
    return files


def scan_file(filepath: Path, verbose: bool = False, logger=None) -> list[dict]:
    findings: list[dict] = []
    max_findings = LIMITS["max_findings_per_file"]

    try:
        size = filepath.stat().st_size
    except OSError:
        return findings

    if size > LIMITS["max_file_size_bytes"]:
        findings.append({"type": "large_file", "pattern": "exceeds_max_size", "severity": "INFO",
                         "file": str(filepath), "line": 0,
                         "snippet": f"size={size} (limit={LIMITS['max_file_size_bytes']})"})
        return findings

    perm = _check_permissions(filepath)
    if perm:
        findings.append(perm)

    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        if verbose and logger:
            logger.debug("Cannot read %s: %s", filepath, exc)
        return findings

    for line_num, line in enumerate(text.splitlines(), 1):
        if len(findings) >= max_findings:
            break
        for pattern_name, regex, severity in SECRET_PATTERNS:
            m = regex.search(line)
            if m:
                findings.append({"type": "secret", "pattern": pattern_name, "severity": severity,
                                  "file": str(filepath), "line": line_num,
                                  "snippet": _snippet(line, m.start())})
        for pattern_name, regex, severity in DANGEROUS_PATTERNS:
            m = regex.search(line)
            if m:
                findings.append({"type": "dangerous_code", "pattern": pattern_name, "severity": severity,
                                  "file": str(filepath), "line": line_num, "snippet": ""})
    return findings


def compute_score(findings: list[dict]) -> int:
    score = 100
    for f in findings:
        score -= SCORE_DEDUCTIONS.get(f["severity"], 0)
    return max(0, score)


def aggregate_by_severity(findings: list[dict]) -> dict[str, int]:
    counts = {sev: 0 for sev in SEVERITY}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts


def top_critical_findings(findings: list[dict], n: int = 10) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY.get(f.get("severity", "INFO"), 0), reverse=True)[:n]


def format_text_report(target, total_files, findings, severity_counts, score, verdict, elapsed):
    lines = []
    lines.append("=" * 70)
    lines.append("  007 QUICK SCAN REPORT")
    lines.append("=" * 70)
    lines.append(f"  Target:        {target}")
    lines.append(f"  Timestamp:     {get_timestamp()}")
    lines.append(f"  Duration:      {elapsed:.2f}s")
    lines.append(f"  Files scanned: {total_files}")
    lines.append(f"  Total findings:{len(findings)}")
    lines.append("")
    lines.append("-" * 70)
    lines.append("  FINDINGS BY SEVERITY")
    lines.append("-" * 70)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = severity_counts.get(sev, 0)
        lines.append(f"    {sev:<10} {count:>5}  {'#' * min(count, 40)}")
    lines.append("")
    top = top_critical_findings(findings)
    if top:
        lines.append("-" * 70)
        lines.append("  TOP FINDINGS (most critical first)")
        lines.append("-" * 70)
        for i, f in enumerate(top, 1):
            snippet_part = f"  [{_redact(f['snippet'])}]" if f.get("snippet") else ""
            lines.append(f"    {i:>2}. [{f['severity']:<8}] {f['type']}/{f['pattern']}")
            lines.append(f"        {f['file']}:{f['line']}{snippet_part}")
        lines.append("")
    lines.append("=" * 70)
    lines.append(f"  QUICK SCORE:  {score} / 100")
    lines.append(f"  VERDICT:      {verdict['emoji']} {verdict['label']}")
    lines.append(f"                {verdict['description']}")
    lines.append("=" * 70)
    lines.append("")
    return "\n".join(lines)


def build_json_report(target, total_files, findings, severity_counts, score, verdict, elapsed):
    return {
        "scan": "quick_scan", "target": target, "timestamp": get_timestamp(),
        "duration_seconds": round(elapsed, 3), "total_files_scanned": total_files,
        "total_findings": len(findings), "severity_counts": severity_counts,
        "score": score,
        "verdict": {"label": verdict["label"], "description": verdict["description"], "emoji": verdict["emoji"]},
        "findings": findings,
    }


def run_scan(target_path: str, output_format: str = "text", verbose: bool = False) -> dict:
    logger = setup_logging("007-quick-scan")
    ensure_directories()

    target = Path(target_path).resolve()
    if not target.exists() or not target.is_dir():
        logger.error("Target path does not exist or is not a directory: %s", target)
        sys.exit(1)

    logger.info("Starting quick scan of %s", target)
    start_time = time.time()

    files = collect_files(target, logger)
    total_files = len(files)
    logger.info("Collected %d scannable files", total_files)

    all_findings: list[dict] = []
    max_report = LIMITS["max_report_findings"]

    for fpath in files:
        if len(all_findings) >= max_report:
            logger.warning("Reached max_report_findings limit. Truncating.")
            break
        file_findings = scan_file(fpath, verbose=verbose, logger=logger)
        remaining = max_report - len(all_findings)
        all_findings.extend(file_findings[:remaining])

    elapsed = time.time() - start_time
    logger.info("Scan complete: %d files, %d findings in %.2fs", total_files, len(all_findings), elapsed)

    severity_counts = aggregate_by_severity(all_findings)
    score = compute_score(all_findings)
    verdict = get_verdict(score)

    log_audit_event("quick_scan", str(target),
        f"score={score}, findings={len(all_findings)}, verdict={verdict['label']}",
        {"total_files": total_files, "severity_counts": severity_counts,
         "duration_seconds": round(elapsed, 3)})

    report = build_json_report(str(target), total_files, all_findings, severity_counts, score, verdict, elapsed)

    if output_format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_text_report(str(target), total_files, all_findings, severity_counts, score, verdict, elapsed))

    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="007 Quick Scan -- Fast automated security scan.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--verbose", action="store_true", default=False)
    args = parser.parse_args()
    run_scan(target_path=args.target, output_format=args.output, verbose=args.verbose)
