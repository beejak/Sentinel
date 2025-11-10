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


def repo_scan(*, path: Optional[str], repo: Optional[str], semgrep_docker: bool) -> Dict[str, Any]:
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

        # Prefer local semgrep if available, else docker if requested/available
        use_docker = False
        semgrep_cmd: List[str]
        if _which("semgrep") and not semgrep_docker:
            semgrep_cmd = ["semgrep", "scan", "--config", "auto", "--json", "--quiet", work]
        else:
            if not _which("docker"):
                return {"error": "semgrep_missing", "message": "Install semgrep or docker to run repo-scan"}
            use_docker = True
            semgrep_cmd = [
                "docker", "run", "--rm",
                "-v", f"{work}:/src",
                "returntocorp/semgrep:latest",
                "semgrep", "scan", "--config", "auto", "--json", "--quiet", "/src"
            ]
        code, out, err = _run(semgrep_cmd, cwd=work)
        if code not in (0, 1):  # semgrep returns 1 when findings are present
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
            findings.append({
                "ruleId": f"SEMGREP::{rule_id}",
                "severity": sev,
                "title": title,
                "evidence": {
                    "path": (r.get("path") or r.get("extra", {}).get("path")),
                    "start": r.get("start"),
                    "end": r.get("end"),
                },
            })
        return {"engine": "semgrep", "path": work, "findings": findings, "docker": use_docker}
    finally:
        if cleanup and work and os.path.isdir(work):
            # Keep for debugging? For now we do not delete automatically; caller can manage tempdir.
            pass
