@echo off
title SABRO VISION - Sync to GitHub & Render
cd /d "%~dp0"
echo ======================================================
echo   SABRO VISION - 1-Click GitHub Push & Render Deploy
echo ======================================================
echo.
powershell -ExecutionPolicy Bypass -File "%~dp0auto_sync.ps1" -Once
echo.
pause
