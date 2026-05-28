"""007 Injection Scanner -- Multi-type injection vulnerability detection.

Detects SQL injection, command injection, code injection, XSS, SSRF,
path traversal, prompt injection, template injection, and XXE across
Python, JavaScript/Node.js, PHP, and shell codebases.

Usage:
    python injection_scanner.py --target /path/to/project
    python injection_scanner.py --target /path/to/project --output json --verbose
"""

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import (
    SCANNABLE_EXTENSIONS,
    SKIP_DIRECTORIES,
    LIMITS,
    SEVERITY,
    ensure_directories,
    get_verdict,
    get_timestamp,
    log_audit_event,
    setup_logging,
)

logger = setup_logging("007-injection-scanner")

SCORE_DEDUCTIONS: dict[str, int] = {
    "CRITICAL": 12,
    "HIGH": 6,
    "MEDIUM": 3,
    "LOW": 1,
    "INFO": 0,
}

# Markers that suggest user-controlled input is nearby
_USER_INPUT_RE = re.compile(
    r"""(?i)(?:request\.|req\.|params\.|query\.|body\.|form\.|"""
    r"""input\.|argv\[|sys\.argv|os\.environ|getenv|"""
    r"""\binput\s*\(|raw_input\s*\()"""
)

# ---------------------------------------------------------------------------
# Injection patterns: (name, injection_type, regex, severity, description)
# ---------------------------------------------------------------------------
INJECTION_PATTERNS: list[tuple[str, str, re.Pattern, str, str]] = [

    # ---- SQL Injection ----
    ("sql_string_format", "sql_injection",
     re.compile(r"""(?i)(?:\.execute|\.query|cursor\.execute|db\.execute|session\.execute)\s*\(\s*[f"'].*%[sd]"""),
     "CRITICAL", "SQL query built with %-string formatting"),

    ("sql_format_method", "sql_injection",
     re.compile(r"""(?i)(?:\.execute|\.query)\s*\(\s*["'].*\{[^}]*\}.*["']\.format\s*\("""),
     "HIGH", "SQL query built with .format()"),

    ("sql_fstring", "sql_injection",
     re.compile(r"""(?i)(?:\.execute|\.query)\s*\(\s*f["'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)"""),
     "HIGH", "SQL query built with f-string"),

    ("sql_concatenation", "sql_injection",
     re.compile(r"""(?i)["']\s*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*["']\s*\+"""),
     "HIGH", "SQL query built by string concatenation"),

    ("knex_raw_variable", "sql_injection",
     re.compile(r"""knex\.raw\s*\(\s*[^'")\s]"""),
     "HIGH", "knex.raw() with non-literal argument (SQL injection risk)"),

    # ---- Command Injection ----
    ("subprocess_shell_true", "command_injection",
     re.compile(r"""subprocess\.[a-z_]+\([^)]*shell\s*=\s*True"""),
     "CRITICAL", "subprocess called with shell=True"),

    ("os_system", "command_injection",
     re.compile(r"""\bos\.system\s*\("""),
     "HIGH", "os.system() — no input sanitization"),

    ("os_popen", "command_injection",
     re.compile(r"""\bos\.popen\s*\("""),
     "HIGH", "os.popen() — no input sanitization"),

    ("node_exec_concat", "command_injection",
     re.compile(r"""(?:exec|execSync|execFile|spawnSync)\s*\([^)]*\+[^)]*\)"""),
     "HIGH", "Node.js command execution with string concatenation"),

    ("php_shell_exec", "command_injection",
     re.compile(r"""(?:exec|shell_exec|system|passthru|popen)\s*\(\s*\$"""),
     "HIGH", "PHP shell execution with variable input"),

    ("ruby_backtick", "command_injection",
     re.compile(r"""`[^`]*#\{"""),
     "HIGH", "Ruby backtick command with interpolation"),

    # ---- Code Injection ----
    ("eval_user_input", "code_injection",
     re.compile(r"""\beval\s*\([^)]*(?:request|input|param|user|argv|environ)"""),
     "CRITICAL", "eval() with user-controlled input"),

    ("eval_any", "code_injection",
     re.compile(r"""\beval\s*\("""),
     "HIGH", "eval() usage"),

    ("exec_user_input", "code_injection",
     re.compile(r"""\bexec\s*\([^)]*(?:request|input|param|user|argv|environ)"""),
     "CRITICAL", "exec() with user-controlled input"),

    ("pickle_loads", "code_injection",
     re.compile(r"""\bpickle\.loads?\s*\("""),
     "HIGH", "pickle.load() — arbitrary code execution on untrusted data"),

    ("yaml_unsafe_load", "code_injection",
     re.compile(r"""\byaml\.load\s*\([^,)]+\)"""),
     "HIGH", "yaml.load() without SafeLoader — code execution risk"),

    ("compile_exec", "code_injection",
     re.compile(r"""compile\s*\([^,]+,\s*['"]\w+['"]\s*,\s*['"]exec['"]"""),
     "HIGH", "compile() + exec() dynamic code execution pattern"),

    ("js_function_constructor", "code_injection",
     re.compile(r"""new\s+Function\s*\([^)]*[+`]"""),
     "HIGH", "new Function() with dynamic string — code injection risk"),

    # ---- XSS ----
    ("innerhtml_variable", "xss",
     re.compile(r"""\.innerHTML\s*[+]?=\s*(?!['"` ]*<)"""),
     "HIGH", "innerHTML assignment with non-literal value (XSS risk)"),

    ("document_write_variable", "xss",
     re.compile(r"""document\.write\s*\(\s*(?!['"` ])"""),
     "HIGH", "document.write() with variable input (XSS risk)"),

    ("jquery_html_variable", "xss",
     re.compile(r"""\$\([^)]+\)\.html\s*\(\s*(?!['"` ])"""),
     "MEDIUM", "jQuery .html() with variable input (XSS risk)"),

    ("jinja_autoescape_off", "xss",
     re.compile(r"""(?i)autoescape\s*=\s*False"""),
     "HIGH", "Jinja2 autoescape disabled — XSS risk"),

    ("react_dangerous_html", "xss",
     re.compile(r"""dangerouslySetInnerHTML"""),
     "MEDIUM", "React dangerouslySetInnerHTML — verify value is sanitized"),

    # ---- SSRF ----
    ("requests_variable_url", "ssrf",
     re.compile(r"""requests\.(?:get|post|put|delete|patch|head|options)\s*\(\s*(?!['"` ])"""),
     "MEDIUM", "HTTP request with variable URL (SSRF risk)"),

    ("fetch_variable_url", "ssrf",
     re.compile(r"""\bfetch\s*\(\s*(?!['"` ])"""),
     "MEDIUM", "fetch() with variable URL (SSRF risk)"),

    ("urllib_variable_url", "ssrf",
     re.compile(r"""urllib\.request\.\w+\s*\(\s*(?!['"` ])"""),
     "MEDIUM", "urllib.request with variable URL (SSRF risk)"),

    # ---- Path Traversal ----
    ("open_dynamic_path", "path_traversal",
     re.compile(r"""\bopen\s*\([^)]*(?:\+|\.format\s*\(|f["'])"""),
     "HIGH", "File open with dynamic path (path traversal risk)"),

    ("path_join_user_input", "path_traversal",
     re.compile(r"""os\.path\.join\s*\([^)]*(?:request|input|param|user|argv)"""),
     "HIGH", "os.path.join with user-controlled input"),

    ("dotdot_sequence", "path_traversal",
     re.compile(r"""\.\.[\\/]"""),
     "MEDIUM", "Hardcoded path traversal sequence '../'"),

    ("send_file_variable", "path_traversal",
     re.compile(r"""(?:send_file|send_from_directory|sendFile)\s*\([^)]*(?:request|input|param|user)"""),
     "HIGH", "File send with user-controlled path"),

    # ---- Prompt Injection ----
    ("user_input_in_messages", "prompt_injection",
     re.compile(r"""(?i)(?:messages|prompt|system)\s*(?:\+?=|\[)\s*.*(?:user_input|request\.|query\.|input\.)"""),
     "MEDIUM", "User input directly interpolated into LLM prompt/messages"),

    ("system_prompt_override", "prompt_injection",
     re.compile(r"""(?i)(?:ignore|disregard|forget)\s+(?:previous|above|prior|all)\s+(?:instructions?|context|prompt)"""),
     "HIGH", "Prompt injection string in codebase ('ignore previous instructions')"),

    # ---- Template Injection (SSTI) ----
    ("render_template_string_user", "template_injection",
     re.compile(r"""render_template_string\s*\([^)]*(?:request|input|param|user|f["'])"""),
     "CRITICAL", "Jinja2 render_template_string with dynamic input (SSTI)"),

    ("template_user_input", "template_injection",
     re.compile(r"""Template\s*\([^)]*(?:request|input|param|user)"""),
     "HIGH", "Template instantiation with user input"),

    # ---- XXE ----
    ("xml_external_entities", "xxe",
     re.compile(r"""(?:XMLParser|etree\.XMLParser|lxml\.etree).*resolve_entities\s*=\s*True"""),
     "HIGH", "XML parser with external entity resolution enabled (XXE)"),

    ("stdlib_xml_import", "xxe",
     re.compile(r"""^import\s+xml\.etree|^from\s+xml\.etree"""),
     "LOW", "Standard xml.etree detected — consider defusedxml"),

    # ---- Open Redirect ----
    ("open_redirect", "open_redirect",
     re.compile(r"""(?:redirect|location)\s*\(\s*(?:request\.|req\.|params\.|query\.)"""),
     "MEDIUM", "Open redirect with user-controlled URL"),
]


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def _should_skip_dir(name: str) -> bool:
    return name in SKIP_DIRECTORIES


def _is_scannable(path: Path) -> bool:
    name = path.name.lower()
    for ext in SCANNABLE_EXTENSIONS:
        if name.endswith(ext):
            return True
    return path.suffix.lower() in SCANNABLE_EXTENSIONS


def collect_files(target: Path) -> list[Path]:
    files: list[Path] = []
    max_files = LIMITS["max_files_per_scan"]
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if not _should_skip_dir(d)]
        for fname in filenames:
            if len(files) >= max_files:
                return files
            fpath = Path(root) / fname
            if _is_scannable(fpath):
                files.append(fpath)
    return files


def _is_comment_or_doc(line: str, ext: str) -> bool:
    s = line.strip()
    if ext in (".py", ".rb", ".sh", ".bash", ".yaml", ".yml", ".toml"):
        return s.startswith("#") or s.startswith('"""') or s.startswith("'''")
    if ext in (".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rs", ".c", ".cpp"):
        return s.startswith("//") or s.startswith("/*") or s.startswith("*")
    return False


def _has_nearby_user_input(lines: list[str], line_idx: int, window: int = 5) -> bool:
    """Return True if any line within ±window contains a user-input marker."""
    start = max(0, line_idx - window)
    end = min(len(lines), line_idx + window + 1)
    return any(_USER_INPUT_RE.search(l) for l in lines[start:end])


# ---------------------------------------------------------------------------
# Core scanning
# ---------------------------------------------------------------------------

def scan_file(
    filepath: Path,
    verbose: bool = False,
    include_low: bool = True,
) -> list[dict]:
    """Scan a single file for injection vulnerabilities."""
    findings: list[dict] = []
    file_str = str(filepath)
    ext = filepath.suffix.lower()

    try:
        size = filepath.stat().st_size
        if size > LIMITS["max_file_size_bytes"]:
            return findings
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        if verbose:
            logger.debug("Cannot read %s: %s", filepath, exc)
        return findings

    lines = text.splitlines()

    for line_idx, line in enumerate(lines):
        if len(findings) >= LIMITS["max_findings_per_file"]:
            break

        if _is_comment_or_doc(line, ext):
            continue

        line_num = line_idx + 1

        for pattern_name, injection_type, regex, base_severity, description in INJECTION_PATTERNS:
            if not include_low and base_severity == "LOW":
                continue

            if not regex.search(line):
                continue

            # Context-aware severity adjustment — downgrade if no user input nearby
            severity = base_severity
            if base_severity in ("CRITICAL", "HIGH"):
                if not _has_nearby_user_input(lines, line_idx):
                    severity = "HIGH" if base_severity == "CRITICAL" else "MEDIUM"

            findings.append({
                "type": "injection",
                "injection_type": injection_type,
                "pattern": pattern_name,
                "severity": severity,
                "file": file_str,
                "line": line_num,
                "description": description,
                "snippet": line.strip()[:80],
            })

    return findings


# ---------------------------------------------------------------------------
# Aggregation & scoring
# ---------------------------------------------------------------------------

def compute_score(findings: list[dict]) -> int:
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


def aggregate_by_type(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        itype = f.get("injection_type", "unknown")
        counts[itype] = counts.get(itype, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------

def format_text_report(
    target: str,
    total_files: int,
    findings: list[dict],
    severity_counts: dict[str, int],
    type_counts: dict[str, int],
    score: int,
    verdict: dict,
    elapsed: float,
) -> str:
    lines: list[str] = []
    lines.append("=" * 72)
    lines.append("  007 INJECTION SCANNER REPORT")
    lines.append("=" * 72)
    lines.append(f"  Target:         {target}")
    lines.append(f"  Timestamp:      {get_timestamp()}")
    lines.append(f"  Duration:       {elapsed:.2f}s")
    lines.append(f"  Files scanned:  {total_files}")
    lines.append(f"  Total findings: {len(findings)}")
    lines.append("")

    lines.append("-" * 72)
    lines.append("  FINDINGS BY SEVERITY")
    lines.append("-" * 72)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = severity_counts.get(sev, 0)
        lines.append(f"    {sev:<10} {count:>5}  {'#' * min(count, 40)}")
    lines.append("")

    if type_counts:
        lines.append("-" * 72)
        lines.append("  FINDINGS BY INJECTION TYPE")
        lines.append("-" * 72)
        for itype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
            lines.append(f"    {itype:<30} {count:>5}")
        lines.append("")

    top = sorted(findings, key=lambda f: SEVERITY.get(f.get("severity", "INFO"), 0), reverse=True)[:10]
    if top:
        lines.append("-" * 72)
        lines.append("  TOP FINDINGS")
        lines.append("-" * 72)
        for f in top:
            lines.append(f"    [{f['severity']:<8}] {f['injection_type']}/{f['pattern']}")
            lines.append(f"             {f['file']}:{f['line']}")
        lines.append("")

    lines.append("=" * 72)
    lines.append(f"  INJECTION SCORE:  {score} / 100")
    lines.append(f"  VERDICT:          {verdict['emoji']} {verdict['label']}")
    lines.append(f"                    {verdict['description']}")
    lines.append("=" * 72)
    lines.append("")
    return "\n".join(lines)


def build_json_report(
    target: str,
    total_files: int,
    findings: list[dict],
    severity_counts: dict[str, int],
    type_counts: dict[str, int],
    score: int,
    verdict: dict,
    elapsed: float,
) -> dict:
    return {
        "scan": "injection_scanner",
        "target": target,
        "timestamp": get_timestamp(),
        "duration_seconds": round(elapsed, 3),
        "total_files_scanned": total_files,
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "injection_type_counts": type_counts,
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
    include_low: bool = True,
) -> dict:
    """Execute the injection scan and return the report dict."""
    if verbose:
        logger.setLevel("DEBUG")

    ensure_directories()
    target = Path(target_path).resolve()

    if not target.exists() or not target.is_dir():
        logger.error("Target path does not exist or is not a directory: %s", target)
        sys.exit(1)

    logger.info("Starting injection scan of %s", target)
    start_time = time.time()

    files = collect_files(target)
    total_files = len(files)
    all_findings: list[dict] = []
    max_report = LIMITS["max_report_findings"]

    for fpath in files:
        if len(all_findings) >= max_report:
            logger.warning("Reached max_report_findings limit. Truncating.")
            break
        file_findings = scan_file(fpath, verbose=verbose, include_low=include_low)
        remaining = max_report - len(all_findings)
        all_findings.extend(file_findings[:remaining])

    elapsed = time.time() - start_time
    severity_counts = aggregate_by_severity(all_findings)
    type_counts = aggregate_by_type(all_findings)
    score = compute_score(all_findings)
    verdict = get_verdict(score)

    logger.info(
        "Injection scan complete: %d files, %d findings, score=%d in %.2fs",
        total_files, len(all_findings), score, elapsed,
    )

    log_audit_event(
        action="injection_scan",
        target=str(target),
        result=f"score={score}, findings={len(all_findings)}, verdict={verdict['label']}",
        details={
            "total_files": total_files,
            "severity_counts": severity_counts,
            "type_counts": type_counts,
            "duration_seconds": round(elapsed, 3),
        },
    )

    report = build_json_report(
        str(target), total_files, all_findings, severity_counts, type_counts, score, verdict, elapsed,
    )

    if output_format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(format_text_report(
            str(target), total_files, all_findings, severity_counts, type_counts, score, verdict, elapsed,
        ))

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="007 Injection Scanner -- Multi-type injection vulnerability detection.",
    )
    parser.add_argument("--target", required=True, help="Path to the directory to scan.")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--verbose", action="store_true", default=False)
    parser.add_argument("--include-low", dest="include_low", action="store_true", default=True)
    args = parser.parse_args()
    run_scan(
        target_path=args.target,
        output_format=args.output,
        verbose=args.verbose,
        include_low=args.include_low,
    )
