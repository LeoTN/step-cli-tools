Write-Host "[INFO] Checking Poetry installation..." -ForegroundColor Cyan
if (-not (Get-Command poetry -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Poetry is not installed or not in PATH." -ForegroundColor Red
    Write-Host "Install it from: https://python-poetry.org/docs/"
    exit 1
}

Write-Host "[INFO] Checking for deptry installation..." -ForegroundColor Cyan
$deptryInstalled = poetry show deptry 2>$null

if (-not $deptryInstalled) {
    Write-Host "[WARNING] deptry not found. Installing as dev dependency..." -ForegroundColor Yellow
    poetry add --group dev deptry
}

Write-Host "`n[INFO] Running deptry..." -ForegroundColor Cyan
$deptryOutput = poetry run deptry . | Out-String

# Remove ANSI color codes (they can break regex matching)
$cleanOutput = $deptryOutput -replace '\x1B\[[0-9;]*[a-zA-Z]', ''

# Write raw output for reference
Write-Host $cleanOutput

# --- Extract issues ---
$missing = @()
$unused = @()
$transitive = @()

foreach ($line in $cleanOutput) {
    if ($line -match "DEP001\s+'([^']+)'") {
        $missing += $Matches[1]
    }
    elseif ($line -match "DEP002\s+'([^']+)'") {
        $unused += $Matches[1]
    }
    elseif ($line -match "DEP003\s+'([^']+)'") {
        $transitive += $Matches[1]
    }
}

# --- Missing dependencies ---
if ($missing.Count -gt 0) {
    Write-Host "`n[WARNING] Missing dependencies detected:" -ForegroundColor Yellow
    $missing | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }

    $confirmAdd = Read-Host "`nDo you want to add them automatically with Poetry? (Y/n)"
    if ([string]::IsNullOrWhiteSpace($confirmAdd)) { $confirmAdd = "y" }

    if ($confirmAdd -eq "y") {
        foreach ($pkg in $missing) {
            Write-Host "[INFO] Adding package: $pkg" -ForegroundColor Cyan
            poetry add $pkg
        }
    }
    else {
        Write-Host "[INFO] Skipped automatic addition." -ForegroundColor DarkGray
    }
}
else {
    Write-Host "`n[INFO] No missing dependencies found." -ForegroundColor Green
}

# --- Unused dependencies ---
if ($unused.Count -gt 0) {
    Write-Host "`n[WARNING] Unused dependencies detected:" -ForegroundColor Yellow
    $unused | ForEach-Object { Write-Host " - $_" -ForegroundColor Yellow }

    $confirmRemove = Read-Host "`nDo you want to remove them automatically with Poetry? (Y/n)"
    if ([string]::IsNullOrWhiteSpace($confirmRemove)) { $confirmRemove = "y" }

    if ($confirmRemove -eq "y") {
        foreach ($pkg in $unused) {
            Write-Host "[INFO] Removing unused package: $pkg" -ForegroundColor Cyan
            poetry remove $pkg
        }
    }
    else {
        Write-Host "[INFO] Skipped automatic removal." -ForegroundColor DarkGray
    }
}
else {
    Write-Host "`n[INFO] No unused dependencies found." -ForegroundColor Green
}

# --- Transitive dependencies ---
if ($transitive.Count -gt 0) {
    Write-Host "`n[INFO] Transitive dependencies detected:" -ForegroundColor Cyan
    $transitive | ForEach-Object { Write-Host " - $_" -ForegroundColor Cyan }

    $confirmTrans = Read-Host "`nDo you want to explicitly add these transitive dependencies to your pyproject.toml? (Y/n)"
    if ([string]::IsNullOrWhiteSpace($confirmTrans)) { $confirmTrans = "y" }

    if ($confirmTrans -eq "y") {
        foreach ($pkg in $transitive) {
            Write-Host "[INFO] Adding transitive dependency explicitly: $pkg" -ForegroundColor Cyan
            poetry add $pkg
        }
    }
    else {
        Write-Host "[INFO] Skipped explicit addition of transitive dependencies." -ForegroundColor DarkGray
    }
}
else {
    Write-Host "`n[INFO] No transitive dependencies detected." -ForegroundColor Green
}

Write-Host "`n[INFO] Done." -ForegroundColor Cyan
pause
