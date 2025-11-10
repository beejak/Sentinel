@echo off
setlocal
pushd vuln-mcp
go run .
set ERR=%ERRORLEVEL%
popd
exit /b %ERR%
