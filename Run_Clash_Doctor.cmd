@echo off
setlocal
set SCRIPT=%~dp0Clash_Network_Doctor_CN_deeptrace.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
endlocal
