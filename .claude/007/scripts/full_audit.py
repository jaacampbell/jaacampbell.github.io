"""007 Full Audit -- 6-phase comprehensive security analysis pipeline.

Phases:
  1. Surface Mapping    — entry points, dependencies, trust boundaries
  2. Threat Modeling    — STRIDE analysis per component
  3. Technical Checklist — aggregated scanner findings
  4. Red Team Analysis  — realistic attack scenarios
  5. Blue Team Defenses — hardening recommendations
  6. Final Verdict      — weighted domain scores and verdict

Usage:
    python full_audit.py --target /path/to/project
    python full_audit.py --target /path/to/project --output json --verbose
    python full_audit.py --target /path/to/project --phases 1,3,6
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
    SCORING_WEIGHTS,
    SCORING_LABELS,
    SEVERITY,
    LIMITS,
    SKIP_DIRECTORIES,
    SCANNABLE_EXTENSIONS,
    ensure_directories,
    get_verdict,
    get_timestamp,
    log_audit_event,
    setup_logging,
    calculate_weighted_score,
    REPORTS_DIR,
)

sys.path.insert(0, str(Path(__file__).resolve().parent / "scanners"))

import secrets_scanner
import dependency_scanner
import injection_scanner
import quick_scan

logger = setup_logging("007-full-audit")

# ---------------------------------------------------------------------------
# Red team attack scenario templates
# ---------------------------------------------------------------------------
_RED_TEAM_TEMPLATES: dict[str, dict] = {
    "secret": {
        "title": "Credential Theft via Leaked Secret",
        "actor": "External attacker / malicious insider",
        "vector": "Exposed credential in source code, logs, or repository history",
        "impact": "Full account/service compromise; lateral movement to connected systems",
        "likelihood": "HIGH — automated scanners (TruffleHog, GitLeaks) find these in minutes",
    },
    "sql_injection": {
        "title": "Data Exfiltration via SQL Injection",
        "actor": "External attacker",
        "vector": "Malicious SQL payload via HTTP parameter, form field, or API body",
        "impact": "Full database dump; authentication bypass; potential RCE via xp_cmdshell",
        "likelihood": "HIGH — SQLMap automates detection and exploitation",
    },
    "command_injection": {
        "title": "Remote Code Execution via Command Injection",
        "actor": "External attacker",
        "vector": "Malicious shell metacharacters injected into system call",
        "impact": "Full server compromise; pivot to internal network; data exfiltration",
        "likelihood": "CRITICAL — trivial to exploit once found",
    },
    "code_injection": {
        "title": "Remote Code Execution via eval/exec",
        "actor": "External attacker / malicious dependency",
        "vector": "User-controlled string passed to eval(), exec(), or unsafe deserializer",
        "impact": "Arbitrary code execution with application privileges",
        "likelihood": "HIGH — common in legacy Python/Node.js codebases",
    },
    "xss": {
        "title": "Account Takeover via Cross-Site Scripting",
        "actor": "External attacker targeting users",
        "vector": "Stored or reflected XSS via unsanitized user input rendered in browser",
        "impact": "Session hijacking; credential theft; malware delivery to users",
        "likelihood": "MEDIUM — requires user interaction",
    },
    "ssrf": {
        "title": "Internal Service Exposure via SSRF",
        "actor": "External attacker",
        "vector": "Server-side request with user-controlled URL targeting internal endpoints",
        "impact": "Access to internal APIs, metadata services (AWS IMDSv1), cloud credentials",
        "likelihood": "MEDIUM — depends on network segmentation",
    },
    "path_traversal": {
        "title": "Arbitrary File Read via Path Traversal",
        "actor": "External attacker",
        "vector": "../ sequences in file path parameters to escape allowed directory",
        "impact": "Read /etc/passwd, application secrets, private keys, config files",
        "likelihood": "MEDIUM — common in file download/upload features",
    },
    "supply_chain": {
        "title": "Supply Chain Compromise via Unpinned Dependency",
        "actor": "Malicious maintainer / typosquatter",
        "vector": "Unpinned package resolves to malicious version after upstream compromise",
        "impact": "Backdoor in production; credential theft; cryptomining",
        "likelihood": "MEDIUM — increasing frequency of npm/PyPI attacks",
    },
    "prompt_injection": {
        "title": "Data Exfiltration via Prompt Injection",
        "actor": "Malicious end user",
        "vector": "Crafted user input overrides system prompt instructions",
        "impact": "Exfiltrate conversation history, system prompt, connected data sources",
        "likelihood": "HIGH for LLM-powered apps without input filtering",
    },
    "template_injection": {
        "title": "RCE via Server-Side Template Injection",
        "actor": "External attacker",
        "vector": "Template expressions ({{ }}) in user-controlled string rendered by Jinja2/Twig",
        "impact": "Full server compromise — SSTI is equivalent to RCE",
        "likelihood": "HIGH — trivial once template engine identified",
    },
}

# ---------------------------------------------------------------------------
# Blue team remediation templates
# ---------------------------------------------------------------------------
_BLUE_TEAM_TEMPLATES: dict[str, dict] = {
    "secret": {
        "priority": "CRITICAL",
        "effort": "Low",
        "remediations": [
            "Rotate the exposed credential immediately",
            "Move secrets to environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault, Doppler)",
            "Add pre-commit hooks: detect-secrets, gitleaks",
            "Purge secret from git history: git-filter-repo or BFG Repo Cleaner",
            "Enable GitHub secret scanning or equivalent",
        ],
    },
    "sql_injection": {
        "priority": "CRITICAL",
        "effort": "Medium",
        "remediations": [
            "Use parameterized queries / prepared statements exclusively",
            "Never build SQL with string formatting, f-strings, or concatenation",
            "Apply principle of least privilege to database users",
            "Enable WAF rules for SQL injection patterns",
            "Validate and allowlist all user inputs before DB operations",
        ],
    },
    "command_injection": {
        "priority": "CRITICAL",
        "effort": "Medium",
        "remediations": [
            "Use subprocess with a list of arguments (never shell=True with user input)",
            "Validate and allowlist inputs before any shell operation",
            "Run application with minimum required OS privileges",
            "Use os.path functions instead of shell path manipulation",
            "Consider abstraction libraries that avoid shell entirely",
        ],
    },
    "code_injection": {
        "priority": "HIGH",
        "effort": "Medium",
        "remediations": [
            "Remove eval()/exec() — replace with explicit logic or safe AST evaluation",
            "Use pickle only for trusted internal data; use JSON/protobuf for untrusted data",
            "Replace yaml.load() with yaml.safe_load()",
            "Sandbox untrusted code execution (RestrictedPython, subprocess in container)",
        ],
    },
    "xss": {
        "priority": "HIGH",
        "effort": "Low",
        "remediations": [
            "Enable template auto-escaping (Jinja2: autoescape=True)",
            "Use textContent instead of innerHTML for DOM manipulation",
            "Apply Content-Security-Policy headers (script-src, object-src 'none')",
            "Sanitize HTML with bleach or DOMPurify before rendering",
            "Set HttpOnly and Secure flags on session cookies",
        ],
    },
    "ssrf": {
        "priority": "HIGH",
        "effort": "Medium",
        "remediations": [
            "Validate and allowlist permitted URL schemes and domains",
            "Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)",
            "Use IMDSv2 with session tokens on AWS (disable IMDSv1)",
            "Route outbound requests through an egress proxy for logging",
            "Avoid passing user-supplied URLs directly to HTTP client functions",
        ],
    },
    "path_traversal": {
        "priority": "HIGH",
        "effort": "Low",
        "remediations": [
            "Use pathlib.Path.resolve() and verify the resolved path starts with the allowed base",
            "Maintain an allowlist of permitted file names/paths",
            "Run file operations with a dedicated low-privilege account",
            "Strip ../ sequences and URL-encoded variants from user input",
        ],
    },
    "supply_chain": {
        "priority": "HIGH",
        "effort": "Low",
        "remediations": [
            "Pin all dependencies to exact versions (== for pip, exact semver for npm)",
            "Use hash verification (pip install --require-hashes)",
            "Enable Dependabot or Renovate for automated security updates",
            "Audit dependencies with safety (Python) or npm audit",
            "Use a lockfile (requirements.txt hashes, package-lock.json, yarn.lock)",
        ],
    },
    "prompt_injection": {
        "priority": "MEDIUM",
        "effort": "Medium",
        "remediations": [
            "Separate system instructions from user content structurally, not textually",
            "Validate and sanitize user inputs before including in prompts",
            "Implement a prompt injection detection layer (LLM-based or rule-based)",
            "Apply principle of least privilege to tool/function calls the LLM can make",
            "Log and monitor all LLM inputs/outputs for anomalous patterns",
        ],
    },
    "template_injection": {
        "priority": "CRITICAL",
        "effort": "Low",
        "remediations": [
            "Never pass user input to render_template_string() — use render_template() with static filenames",
            "Use Jinja2 SandboxedEnvironment for any dynamic template rendering",
            "Escape all user data before including in template context",
        ],
    },
}


# ---------------------------------------------------------------------------
# Phase 1: Surface Mapping
# ---------------------------------------------------------------------------

def phase1_surface_mapping(target: Path) -> dict:
    """Inventory files, entry points, and dependency files."""
    summary: dict = {
        "total_files": 0,
        "by_extension": {},
        "entry_points": [],
        "dependency_files": [],
        "config_files": [],
        "sensitive_files": [],
    }

    entry_point_patterns = re.compile(
        r"""(?i)(?:app\.py|main\.py|server\.py|index\.js|app\.js|server\.js|"""
        r"""manage\.py|wsgi\.py|asgi\.py|cli\.py|entrypoint\.)"""
    )
    sensitive_patterns = re.compile(
        r"""(?i)(?:\.env|\.pem|\.key|id_rsa|credentials|secrets|\.htpasswd)"""
    )
    config_patterns = re.compile(
        r"""(?i)(?:config\.|settings\.|\.yaml|\.yml|\.toml|\.ini|\.cfg|docker-compose)"""
    )
    dep_patterns = re.compile(
        r"""(?i)(?:requirements|package\.json|pipfile|pyproject\.toml|setup\.py)"""
    )

    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]
        for fname in filenames:
            summary["total_files"] += 1
            fpath = Path(root) / fname
            rel = str(fpath.relative_to(target))
            ext = fpath.suffix.lower() or fname.lower()
            summary["by_extension"][ext] = summary["by_extension"].get(ext, 0) + 1

            if entry_point_patterns.search(fname):
                summary["entry_points"].append(rel)
            if dep_patterns.search(fname):
                summary["dependency_files"].append(rel)
            if sensitive_patterns.search(fname):
                summary["sensitive_files"].append(rel)
            elif config_patterns.search(fname):
                summary["config_files"].append(rel)

    return summary


# ---------------------------------------------------------------------------
# Phase 2: Threat Modeling (STRIDE guidance)
# ---------------------------------------------------------------------------

def phase2_threat_model(surface: dict, findings: list[dict]) -> dict:
    """Generate STRIDE threat model based on surface and findings."""
    finding_types = {f.get("type") for f in findings}
    injection_types = {f.get("injection_type") for f in findings if f.get("injection_type")}

    stride: dict[str, list[str]] = {
        "spoofing": [],
        "tampering": [],
        "repudiation": [],
        "information_disclosure": [],
        "denial_of_service": [],
        "elevation_of_privilege": [],
    }

    if "secret" in finding_types:
        stride["spoofing"].append("Leaked credentials may allow attacker to impersonate legitimate service")
        stride["information_disclosure"].append("Hardcoded secrets expose credentials in source/logs")

    if "sql_injection" in injection_types:
        stride["tampering"].append("SQL injection allows unauthorized data modification or deletion")
        stride["information_disclosure"].append("SQL injection enables full database dump")
        stride["elevation_of_privilege"].append("SQL injection may allow auth bypass or admin access")

    if "command_injection" in injection_types or "code_injection" in injection_types:
        stride["elevation_of_privilege"].append("Command/code injection grants OS-level execution as app user")
        stride["tampering"].append("RCE allows filesystem modification, config tampering")

    if "xss" in injection_types:
        stride["spoofing"].append("XSS allows attacker to act as victim user in browser context")
        stride["information_disclosure"].append("XSS can exfiltrate session tokens and CSRF tokens")

    if "ssrf" in injection_types:
        stride["information_disclosure"].append("SSRF can expose internal services and cloud metadata")
        stride["elevation_of_privilege"].append("SSRF via cloud metadata can yield IAM credentials")

    if "supply_chain" in finding_types:
        stride["tampering"].append("Unpinned dependencies may introduce malicious code via supply chain")
        stride["denial_of_service"].append("Compromised dependency may introduce instability or resource exhaustion")

    if not stride["repudiation"]:
        stride["repudiation"].append("Review audit logging coverage — ensure all auth and data-access events are logged")

    if not stride["denial_of_service"]:
        stride["denial_of_service"].append("Review rate limiting and resource exhaustion protections")

    return {
        "stride": stride,
        "entry_points_analyzed": len(surface.get("entry_points", [])),
        "sensitive_files_found": len(surface.get("sensitive_files", [])),
    }


# ---------------------------------------------------------------------------
# Phase 4: Red Team Analysis
# ---------------------------------------------------------------------------

def phase4_red_team(findings: list[dict]) -> list[dict]:
    """Map findings to attack scenarios."""
    seen_types: set[str] = set()
    scenarios: list[dict] = []

    priority_order = ["command_injection", "template_injection", "code_injection",
                      "sql_injection", "secret", "xss", "ssrf", "path_traversal",
                      "supply_chain", "prompt_injection"]

    # Sort findings by severity then by priority type order
    def _sort_key(f):
        sev = SEVERITY.get(f.get("severity", "INFO"), 0)
        ftype = f.get("injection_type") or f.get("type") or ""
        type_pri = priority_order.index(ftype) if ftype in priority_order else 99
        return (-sev, type_pri)

    for f in sorted(findings, key=_sort_key):
        ftype = f.get("injection_type") or f.get("type") or ""
        if ftype in seen_types:
            continue
        if ftype not in _RED_TEAM_TEMPLATES:
            continue
        seen_types.add(ftype)
        template = _RED_TEAM_TEMPLATES[ftype]
        scenarios.append({
            "finding_type": ftype,
            "severity": f.get("severity", "UNKNOWN"),
            "example_location": f"{f.get('file', '?')}:{f.get('line', '?')}",
            **template,
        })

    return scenarios


# ---------------------------------------------------------------------------
# Phase 5: Blue Team Defenses
# ---------------------------------------------------------------------------

def phase5_blue_team(findings: list[dict]) -> list[dict]:
    """Generate hardening recommendations from findings."""
    seen_types: set[str] = set()
    recommendations: list[dict] = []

    for f in sorted(findings, key=lambda x: SEVERITY.get(x.get("severity", "INFO"), 0), reverse=True):
        ftype = f.get("injection_type") or f.get("type") or ""
        if ftype in seen_types:
            continue
        if ftype not in _BLUE_TEAM_TEMPLATES:
            continue
        seen_types.add(ftype)
        recommendations.append({
            "finding_type": ftype,
            "example_location": f"{f.get('file', '?')}:{f.get('line', '?')}",
            **_BLUE_TEAM_TEMPLATES[ftype],
        })

    return recommendations


# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------

def _format_markdown_report(
    target: str,
    surface: dict,
    threat_model: dict,
    findings: list[dict],
    red_team: list[dict],
    blue_team: list[dict],
    domain_scores: dict[str, float],
    final_score: float,
    verdict: dict,
    elapsed: float,
) -> str:
    lines: list[str] = []
    lines.append(f"# 007 Security Audit Report\n")
    lines.append(f"**Target:** `{target}`  ")
    lines.append(f"**Date:** {get_timestamp()}  ")
    lines.append(f"**Duration:** {elapsed:.1f}s\n")

    # Executive summary
    lines.append("## Executive Summary\n")
    crit = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    lines.append(f"Security scan of `{target}` found **{len(findings)} total findings** "
                 f"({crit} CRITICAL, {high} HIGH). "
                 f"Final security score: **{final_score:.0f}/100** — "
                 f"{verdict['emoji']} **{verdict['label']}**.\n")

    # Phase 1
    lines.append("## Phase 1 — Surface Mapping\n")
    lines.append(f"- Total files scanned: **{surface['total_files']}**")
    lines.append(f"- Entry points identified: **{len(surface['entry_points'])}**")
    lines.append(f"- Dependency manifests: **{len(surface['dependency_files'])}**")
    lines.append(f"- Sensitive files detected: **{len(surface['sensitive_files'])}**")
    if surface["entry_points"]:
        lines.append(f"\n**Entry points:** {', '.join(surface['entry_points'][:10])}")
    if surface["sensitive_files"]:
        lines.append(f"\n⚠️ **Sensitive files:** {', '.join(surface['sensitive_files'][:5])}")
    lines.append("")

    # Phase 2
    lines.append("## Phase 2 — Threat Model (STRIDE)\n")
    for threat_type, items in threat_model.get("stride", {}).items():
        if items:
            lines.append(f"**{threat_type.replace('_', ' ').title()}:**")
            for item in items:
                lines.append(f"- {item}")
    lines.append("")

    # Phase 3
    lines.append("## Phase 3 — Technical Checklist\n")
    by_sev: dict[str, list[dict]] = {}
    for f in findings:
        by_sev.setdefault(f.get("severity", "INFO"), []).append(f)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        sev_findings = by_sev.get(sev, [])
        if sev_findings:
            lines.append(f"### {sev} ({len(sev_findings)} findings)\n")
            for f in sev_findings[:10]:
                ftype = f.get("injection_type") or f.get("type") or "unknown"
                lines.append(f"- `{f.get('file', '?')}:{f.get('line', '?')}` — "
                             f"**{ftype}/{f.get('pattern', '?')}**")
            if len(sev_findings) > 10:
                lines.append(f"- *(+{len(sev_findings)-10} more)*")
            lines.append("")

    # Phase 4
    lines.append("## Phase 4 — Red Team Analysis\n")
    if red_team:
        for scenario in red_team:
            lines.append(f"### {scenario['title']}")
            lines.append(f"- **Severity:** {scenario['severity']}")
            lines.append(f"- **Actor:** {scenario['actor']}")
            lines.append(f"- **Vector:** {scenario['vector']}")
            lines.append(f"- **Impact:** {scenario['impact']}")
            lines.append(f"- **Likelihood:** {scenario['likelihood']}")
            lines.append(f"- **Example location:** `{scenario['example_location']}`\n")
    else:
        lines.append("No critical attack scenarios identified.\n")

    # Phase 5
    lines.append("## Phase 5 — Blue Team Defenses\n")
    if blue_team:
        for rec in blue_team:
            lines.append(f"### {rec['finding_type'].replace('_', ' ').title()} "
                        f"(Priority: {rec['priority']}, Effort: {rec['effort']})")
            for r in rec["remediations"]:
                lines.append(f"- {r}")
            lines.append("")
    else:
        lines.append("No remediation recommendations (clean scan).\n")

    # Phase 6
    lines.append("## Phase 6 — Final Verdict\n")
    lines.append("| Domain | Weight | Score |")
    lines.append("|--------|--------|-------|")
    for domain, weight in SCORING_WEIGHTS.items():
        score = domain_scores.get(domain, 0.0)
        label = SCORING_LABELS.get(domain, domain)
        bar = "█" * int(score / 10) + "░" * (10 - int(score / 10))
        lines.append(f"| {label} | {weight*100:.0f}% | {score:.0f} {bar} |")
    lines.append("")
    lines.append(f"**Final Score: {final_score:.1f} / 100**\n")
    lines.append(f"## {verdict['emoji']} Verdict: {verdict['label']}\n")
    lines.append(f"> {verdict['description']}\n")

    # Top 3 action items
    lines.append("## Top 3 Action Items\n")
    critical_findings = [f for f in findings if f.get("severity") == "CRITICAL"]
    action_types: list[str] = []
    for f in critical_findings:
        ftype = f.get("injection_type") or f.get("type") or ""
        if ftype not in action_types and ftype in _BLUE_TEAM_TEMPLATES:
            action_types.append(ftype)
    for i, ftype in enumerate(action_types[:3], 1):
        rec = _BLUE_TEAM_TEMPLATES[ftype]
        lines.append(f"{i}. **Fix {ftype.replace('_', ' ')}** — {rec['remediations'][0]}")
    if not action_types:
        lines.append("1. Continue monitoring and review MEDIUM findings for risk acceptance.")
    lines.append("")

    return "\n".join(lines)


def _format_text_report(target, surface, threat_model, findings,
                         red_team, blue_team, domain_scores, final_score, verdict, elapsed):
    lines = []
    lines.append("=" * 72)
    lines.append("  007 FULL SECURITY AUDIT REPORT")
    lines.append("=" * 72)
    lines.append(f"  Target:   {target}")
    lines.append(f"  Date:     {get_timestamp()}")
    lines.append(f"  Duration: {elapsed:.1f}s")
    lines.append("")

    crit = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    lines.append(f"  EXECUTIVE SUMMARY")
    lines.append(f"  {len(findings)} total findings ({crit} CRITICAL, {high} HIGH)")
    lines.append(f"  Final score: {final_score:.0f}/100 — {verdict['emoji']} {verdict['label']}")
    lines.append("")

    lines.append("-" * 72)
    lines.append("  PHASE 1 — SURFACE MAPPING")
    lines.append("-" * 72)
    lines.append(f"  Files: {surface['total_files']}  "
                f"Entry points: {len(surface['entry_points'])}  "
                f"Sensitive files: {len(surface['sensitive_files'])}")
    if surface["sensitive_files"]:
        lines.append(f"  ⚠  Sensitive: {', '.join(surface['sensitive_files'][:5])}")
    lines.append("")

    lines.append("-" * 72)
    lines.append("  PHASE 3 — TOP FINDINGS")
    lines.append("-" * 72)
    top = sorted(findings, key=lambda f: SEVERITY.get(f.get("severity", "INFO"), 0), reverse=True)[:15]
    for f in top:
        ftype = f.get("injection_type") or f.get("type") or "?"
        lines.append(f"  [{f.get('severity','?'):<8}] {ftype}/{f.get('pattern','?')}")
        lines.append(f"             {f.get('file','?')}:{f.get('line','?')}")
    lines.append("")

    lines.append("-" * 72)
    lines.append("  PHASE 6 — DOMAIN SCORES")
    lines.append("-" * 72)
    for domain, weight in SCORING_WEIGHTS.items():
        score = domain_scores.get(domain, 0.0)
        label = SCORING_LABELS.get(domain, domain)
        bar = "#" * int(score / 5) + "." * (20 - int(score / 5))
        lines.append(f"  {label:<30} {weight*100:.0f}%  {score:>5.1f}  [{bar}]")
    lines.append("")
    lines.append("=" * 72)
    lines.append(f"  FINAL SCORE:  {final_score:.1f} / 100")
    lines.append(f"  VERDICT:      {verdict['emoji']} {verdict['label']}")
    lines.append(f"                {verdict['description']}")
    lines.append("=" * 72)
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_audit(
    target_path: str,
    output_format: str = "text",
    verbose: bool = False,
    phases: list[int] | None = None,
) -> dict:
    """Execute the full 6-phase audit and return the report dict."""
    if verbose:
        logger.setLevel("DEBUG")

    ensure_directories()
    target = Path(target_path).resolve()

    if not target.exists() or not target.is_dir():
        logger.error("Target does not exist or is not a directory: %s", target)
        sys.exit(1)

    run_all = not phases
    active_phases = set(phases or range(1, 7))

    logger.info("Starting full audit of %s (phases: %s)", target,
                "all" if run_all else sorted(active_phases))
    start_time = time.time()
    target_str = str(target)

    def _safe_scan(scanner_module, **kwargs):
        try:
            return scanner_module.run_scan(**kwargs)
        except SystemExit:
            return {"findings": [], "score": 50}

    # --- Collect all findings (always needed) ---
    logger.info("Running scanners...")
    secrets_report = _safe_scan(secrets_scanner, target_path=target_str, output_format="json", verbose=verbose)
    dep_report = _safe_scan(dependency_scanner, target_path=target_str, output_format="json", verbose=verbose)
    inj_report = _safe_scan(injection_scanner, target_path=target_str, output_format="json", verbose=verbose)
    quick_report = _safe_scan(quick_scan, target_path=target_str, output_format="json", verbose=verbose)

    all_raw = (secrets_report.get("findings", []) + dep_report.get("findings", []) +
               inj_report.get("findings", []) + quick_report.get("findings", []))

    # Deduplicate
    seen: set[tuple] = set()
    all_findings: list[dict] = []
    for f in all_raw:
        key = (f.get("file", ""), f.get("line", 0), f.get("pattern", ""))
        if key not in seen:
            seen.add(key)
            all_findings.append(f)

    logger.info("Total unique findings: %d", len(all_findings))

    # Phase 1
    surface = phase1_surface_mapping(target) if 1 in active_phases else {}
    logger.info("Phase 1 complete: %d files", surface.get("total_files", 0))

    # Phase 2
    threat_model = phase2_threat_model(surface, all_findings) if 2 in active_phases else {}
    logger.info("Phase 2 complete: STRIDE model generated")

    # Phase 4
    red_team = phase4_red_team(all_findings) if 4 in active_phases else []
    logger.info("Phase 4 complete: %d attack scenarios", len(red_team))

    # Phase 5
    blue_team = phase5_blue_team(all_findings) if 5 in active_phases else []
    logger.info("Phase 5 complete: %d hardening recommendations", len(blue_team))

    # Phase 6 — scoring
    from score_calculator import compute_domain_scores, _collect_source_files
    source_files = _collect_source_files(target)
    domain_scores = compute_domain_scores(
        secrets_findings=secrets_report.get("findings", []),
        injection_findings=inj_report.get("findings", []),
        dependency_report=dep_report,
        quick_findings=quick_report.get("findings", []),
        source_files=source_files,
        total_source_files=len(source_files),
    ) if 6 in active_phases else {k: 50.0 for k in SCORING_WEIGHTS}

    final_score = calculate_weighted_score(domain_scores)
    verdict = get_verdict(final_score)
    elapsed = time.time() - start_time

    logger.info("Full audit complete in %.1fs — score=%.1f, verdict=%s",
                elapsed, final_score, verdict["label"])

    # Save markdown report
    if output_format in ("text", "markdown") and 6 in active_phases:
        report_path = REPORTS_DIR / f"audit_{get_timestamp().replace(':', '-')}.md"
        try:
            md = _format_markdown_report(target_str, surface, threat_model, all_findings,
                                          red_team, blue_team, domain_scores, final_score, verdict, elapsed)
            report_path.write_text(md, encoding="utf-8")
            logger.info("Markdown report saved: %s", report_path)
        except OSError as exc:
            logger.warning("Could not save markdown report: %s", exc)

    log_audit_event("full_audit", target_str,
        f"final_score={final_score}, findings={len(all_findings)}, verdict={verdict['label']}",
        {"phases": sorted(active_phases), "total_findings": len(all_findings),
         "domain_scores": domain_scores, "duration_seconds": round(elapsed, 3)})

    report = {
        "audit": "full_audit", "target": target_str, "timestamp": get_timestamp(),
        "duration_seconds": round(elapsed, 3), "phases_run": sorted(active_phases),
        "surface": surface, "threat_model": threat_model,
        "total_findings": len(all_findings),
        "red_team_scenarios": red_team, "blue_team_defenses": blue_team,
        "domain_scores": domain_scores, "final_score": final_score,
        "verdict": {"label": verdict["label"], "description": verdict["description"], "emoji": verdict["emoji"]},
    }

    if output_format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(_format_text_report(target_str, surface, threat_model, all_findings,
                                   red_team, blue_team, domain_scores, final_score, verdict, elapsed))

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="007 Full Audit -- 6-phase comprehensive security analysis.",
        epilog="Example: python full_audit.py --target ./my-project --output text",
    )
    parser.add_argument("--target", required=True, help="Path to the directory to audit.")
    parser.add_argument("--output", choices=["text", "json", "markdown"], default="text")
    parser.add_argument("--verbose", action="store_true", default=False)
    parser.add_argument("--phases", default="",
                        help="Comma-separated phases to run, e.g. 1,3,6 (default: all)")
    args = parser.parse_args()

    phases_list: list[int] | None = None
    if args.phases:
        try:
            phases_list = [int(p.strip()) for p in args.phases.split(",") if p.strip()]
        except ValueError:
            print("ERROR: --phases must be comma-separated integers e.g. 1,3,6")
            sys.exit(1)

    run_audit(target_path=args.target, output_format=args.output,
              verbose=args.verbose, phases=phases_list)
