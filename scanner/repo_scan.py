from __future__ import annotations
import json
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional, Tuple


def _which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)


def _run(cmd: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        out, err = p.communicate()
    return p.returncode, out, err


def repo_scan(*, path: Optional[str], repo: Optional[str], semgrep_docker: bool, packs: Optional[List[str]] = None) -> Dict[str, Any]:
    work: Optional[str] = None
    cleanup = False
    try:
        if path:
            work = os.path.abspath(path)
        elif repo:
            if not _which("git"):
                return {"error": "git_not_found", "message": "Install git to scan a repo URL"}
            tmp = tempfile.mkdtemp(prefix="sentinel-scan-")
            cleanup = True
            code, out, err = _run(["git", "clone", "--depth", "1", repo, tmp])
            if code != 0:
                return {"error": "git_clone_failed", "stderr": err}
            work = tmp
        else:
            return {"error": "no_input", "message": "Provide --path or --repo"}

        # Recommended configs (falls back to auto)
        configs = packs if packs else [
            "p/secrets",
            "p/ci",
            "p/r2c-security-audit",
            "p/owasp-top-ten",
        ]
        conf_args: List[str] = []
        for c in configs:
            conf_args += ["--config", c]

        # Prefer local semgrep; else docker if requested/available
        use_docker = False
        semgrep_cmd: List[str]
        if _which("semgrep") and not semgrep_docker:
            semgrep_cmd = ["semgrep", "scan", *conf_args, "--json", "--quiet", work]
        else:
            if not _which("docker"):
                return {"error": "semgrep_missing", "message": "Install semgrep or docker to run repo-scan"}
            use_docker = True
            semgrep_cmd = [
                "docker", "run", "--rm",
                "-v", f"{work}:/src",
                "returntocorp/semgrep:latest",
                "semgrep", "scan", *conf_args, "--json", "--quiet", "/src"
            ]
        code, out, err = _run(semgrep_cmd, cwd=work)
        if code not in (0, 1):  # semgrep returns 1 when findings are present
            # fallback to auto
            if _which("semgrep") and not use_docker:
                semgrep_cmd = ["semgrep", "scan", "--config", "auto", "--json", "--quiet", work]
            else:
                semgrep_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{work}:/src",
                    "returntocorp/semgrep:latest",
                    "semgrep", "scan", "--config", "auto", "--json", "--quiet", "/src"
                ]
            code, out, err = _run(semgrep_cmd, cwd=work)
            if code not in (0,1):
                return {"error": "semgrep_failed", "stderr": err}
        try:
            data = json.loads(out)
        except Exception:
            return {"error": "semgrep_json_error", "stderr": err[:500]}
        results = data.get("results", []) if isinstance(data, dict) else []
        findings: List[Dict[str, Any]] = []
        for r in results:
            rule_id = r.get("check_id") or r.get("rule_id") or "semgrep-rule"
            sev = (r.get("extra", {}).get("metadata", {}).get("severity") or r.get("extra", {}).get("severity") or "medium").lower()
            if sev not in ("low", "medium", "high"):
                sev = {"INFO":"low","WARNING":"medium","ERROR":"high"}.get(str(sev).upper(), "medium")
            title = r.get("extra", {}).get("message") or rule_id
            loc = r.get("extra", {}).get("lines", "")
            cwe = r.get("extra", {}).get("metadata", {}).get("cwe")
            if isinstance(cwe, list) and cwe:
                cwe = cwe[0]
            evidence = {
                "path": (r.get("path") or r.get("extra", {}).get("path")),
                "start": r.get("start"),
                "end": r.get("end"),
                "lines": loc,
            }
            if cwe:
                evidence["cwe"] = cwe
            findings.append({
                "ruleId": f"SEMGREP::{rule_id}",
                "severity": sev,
                "title": title,
                "evidence": evidence,
            })
        return {"engine": "semgrep", "path": work, "findings": findings, "docker": use_docker}
    finally:
        if cleanup and work and os.path.isdir(work):
            # Keep for debugging? For now we do not delete automatically; caller can manage tempdir.
            pass


def repo_scan_to_sarif(result: Dict[str, Any]) -> Dict[str, Any]:
    import hashlib
    findings = result.get("findings", [])
    rules: Dict[str, Dict[str, Any]] = {}
    cwes: List[str] = []
    for f in findings:
        rid = f.get("ruleId")
        if rid and rid not in rules:
            level = {"low":"note","medium":"warning","high":"error"}.get(f.get("severity"),"warning")
            rules[rid] = {
                "id": rid,
                "name": rid,
                "shortDescription": {"text": f.get("title", rid)},
                "defaultConfiguration": {"level": level},
            }
        cwe = (f.get("evidence") or {}).get("cwe")
        if cwe and cwe not in cwes:
            cwes.append(str(cwe))
    results = []
    for f in findings:
        path = str(((f.get("evidence") or {}).get("path")) or "")
        fp = hashlib.sha256(f"{f.get('ruleId')}|{path}".encode()).hexdigest()
        results.append({
            "ruleId": f.get("ruleId"),
            "level": {"low":"note","medium":"warning","high":"error"}.get(f.get("severity"),"warning"),
            "message": {"text": f.get("title")},
            "locations": ([{"physicalLocation": {"artifactLocation": {"uri": path}}}] if path else None),
            "partialFingerprints": {"ruleAndPath": fp},
            "properties": {"evidence": f.get("evidence")},
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "mcp-scanner/semgrep", "rules": list(rules.values())}},
            "taxonomies": [{"name": "CWE", "taxa": [{"id": c} for c in cwes]}] if cwes else [],
            "results": results
        }],
    }


def repo_scan_to_html(result: Dict[str, Any]) -> str:
    import html
    fnds = result.get("findings", [])
    hi = sum(1 for f in fnds if f.get("severity") == "high")
    me = sum(1 for f in fnds if f.get("severity") == "medium")
    lo = sum(1 for f in fnds if f.get("severity") == "low")
    def _sev_cls(s: str) -> str:
        return {'high':'sev-high','medium':'sev-medium','low':'sev-low'}.get(s,'')
    rows = "\n".join(
        f"<tr><td>{html.escape(f.get('ruleId',''))}</td><td class='{_sev_cls(str(f.get('severity','')))}'>{html.escape(f.get('severity',''))}</td><td>{html.escape(f.get('title',''))}</td><td>{html.escape(str((f.get('evidence') or {}).get('path') or ''))}</td></tr>"
        for f in fnds
    )
    return f"""
<!doctype html>
<html><head><meta charset='utf-8'>
<title>Sentinel Repo Scan</title>
<style>body{{font-family:system-ui,Arial,sans-serif;margin:2rem}} table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #ddd;padding:.5rem}} th{{background:#f8f8f8}} .sev-high{{color:#e74c3c}} .sev-medium{{color:#f39c12}} .sev-low{{color:#3498db}} .badge{{display:inline-block;padding:.1rem .4rem;border-radius:.25rem;background:#f0f0f0;margin-right:.5rem}}</style>
</head>
<body>
<h1>Sentinel Repo Scan</h1>
<p><strong>Path:</strong> {html.escape(str(result.get('path','')))}</p>
<p>
  <span class='badge sev-high'>High: {hi}</span>
  <span class='badge sev-medium'>Medium: {me}</span>
  <span class='badge sev-low'>Low: {lo}</span>
</p>
<h2>Findings</h2>
<table><thead><tr><th>Rule</th><th>Severity</th><th>Title</th><th>Path</th></tr></thead>
<tbody>
{rows if rows else '<tr><td colspan=\"4\">No findings</td></tr>'}
</tbody></table>
<p style='margin-top:1rem;color:#666'>Powered by Semgrep rule packs (secrets, ci, security-audit, OWASP Top Ten).</p>
</body></html>
"""
