@echo off
cd /d "%~dp0\..\.."
powershell -NoProfile -ExecutionPolicy Bypass -File labs\lab9\run-lab9.ps1 %1
pause
