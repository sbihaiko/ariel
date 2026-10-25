@echo off
rem Double-click wrapper for Windows: the work is in ariel.ps1, run with the
rem execution policy for this one file only.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0ariel.ps1" %*
if errorlevel 1 pause
