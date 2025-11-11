@echo off
setlocal
REM Launch vuln-mcp with safer behaviors (close known vulnerabilities)
set VULN_ACCEPT_ALG_NONE=false
set VULN_WEAK_RSA_KEY=false
set VULN_NO_HSTS=false
set VULN_DANGEROUS_TOOL=false
set VULN_ALLOW_GET_PUT=false
set VULN_ALLOW_TRACE=false
set VULN_ACCEPT_MISSING_CT=false
set VULN_ALLOW_TRAVERSAL=false
set VULN_PERMISSIVE_TOOL_RUN=false
set VULN_REPLAY_CODE=false
set VULN_ACCEPT_BOGUS_TOKEN=false
set VULN_SSRF_BLOCK=true

call "%~dp0run_vuln_mcp.cmd"
exit /b %ERRORLEVEL%
