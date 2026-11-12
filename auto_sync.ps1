param(
    [switch]$Once,
    [switch]$IncludeDb,
    [int]$PollSeconds = 5,
    [string]$Message = ""
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

function Sync-Changes {
    $userName = (git config user.name 2>$null)
    $userEmail = (git config user.email 2>$null)
    if (-not $userName -or -not $userEmail) {
        Write-Host "[!] Git user.name / user.email not configured yet." -ForegroundColor Yellow
        Write-Host "    Run: git config user.name `"Your Name`"" -ForegroundColor Gray
        Write-Host "    Run: git config user.email `"you@example.com`"" -ForegroundColor Gray
        return $false
    }

    $remoteUrl = (git remote get-url origin 2>$null)
    if (-not $remoteUrl) {
        Write-Host "[!] GitHub 'origin' remote is not connected yet." -ForegroundColor Yellow
        Write-Host "    Run: git remote add origin https://github.com/<USERNAME>/sabro-vision.git" -ForegroundColor Gray
        return $false
    }

    # Check working tree changes (skip runtime SQLite fluctuations unless -IncludeDb is passed)
    if ($IncludeDb) {
        $changes = git status --porcelain
    } else {
        $changes = git status --porcelain | Where-Object { $_ -notmatch "sabro_iptv\.db" }
    }

    if (-not $changes) {
        return $true
    }

    Write-Host "`n[+] Detected changes -> Staging & committing..." -ForegroundColor Cyan
    if ($IncludeDb) {
        git add -A
    } else {
        git add -A -- ':!sabro_iptv.db' ':!sabro_iptv.db-wal' ':!sabro_iptv.db-shm'
    }

    $staged = git diff --cached --name-only
    if (-not $staged) {
        return $true
    }

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $commitMsg = if ($Message) { $Message } else { "Auto-sync SABRO VISION ($ts)" }

    git commit -m $commitMsg
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Commit failed." -ForegroundColor Red
        return $false
    }

    Write-Host "[+] Pushing to GitHub ($remoteUrl)..." -ForegroundColor Cyan
    git push origin main
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Push to GitHub failed. Ensure you are authenticated with GitHub." -ForegroundColor Red
        return $false
    }

    Write-Host "[OK] Pushed to GitHub! Render auto-deploy is triggered automatically via render.yaml." -ForegroundColor Green

    if ($env:RENDER_DEPLOY_HOOK) {
        try {
            Invoke-RestMethod -Uri $env:RENDER_DEPLOY_HOOK -Method Post | Out-Null
            Write-Host "[OK] Render Deploy Hook pinged directly." -ForegroundColor Green
        } catch {
            Write-Host "[!] Render Deploy Hook ping failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }

    return $true
}

if ($Once) {
    $ok = Sync-Changes
    if (-not $ok) { exit 1 }
    exit 0
}

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "  SABRO VISION - Auto-Sync to GitHub & Render" -ForegroundColor White
Write-Host "  Polling every $PollSeconds seconds. Press Ctrl+C to stop." -ForegroundColor Gray
Write-Host "=====================================================" -ForegroundColor Cyan

while ($true) {
    try {
        Sync-Changes | Out-Null
    } catch {
        Write-Host "[!] Sync error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    Start-Sleep -Seconds $PollSeconds
}
