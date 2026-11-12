@echo off
title SABRO VISION - Live Auto-Sync Watcher (GitHub + Render)
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0auto_sync.ps1" -PollSeconds 5
