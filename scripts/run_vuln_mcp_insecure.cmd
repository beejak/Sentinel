@echo off
setlocal
REM Launch vuln-mcp with all insecure behaviors enabled
set VULN_ACCEPT_ALG_NONE=true
set VULN_WEAK_RSA_KEY=true
set VULN_NO_HSTS=true
set VULN_DANGEROUS_TOOL=true
set VULN_ALLOW_GET_PUT=true
set VULN_ALLOW_TRACE=true
set VULN_ACCEPT_MISSING_CT=true
set VULN_ALLOW_TRAVERSAL=true
set VULN_PERMISSIVE_TOOL_RUN=true
set VULN_REPLAY_CODE=true
set VULN_ACCEPT_BOGUS_TOKEN=true
set VULN_SSRF_BLOCK=false

call "%~dp0run_vuln_mcp.cmd"
exit /b %ERRORLEVEL%
