@echo off
setlocal
pushd testharness
go run .
set ERR=%ERRORLEVEL%
popd
exit /b %ERR%
