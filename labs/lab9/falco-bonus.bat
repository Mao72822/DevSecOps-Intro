@echo off
cd /d "%~dp0\..\.."
powershell -NoProfile -ExecutionPolicy Bypass -File labs\lab9\falco-bonus.ps1
pause
