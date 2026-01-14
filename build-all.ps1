Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Docker Build Script - Multi-Layer Spoofing Detection System " -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is not installed or not in PATH."
    exit 1
}

try {
    docker info | Out-Null
} catch {
    Write-Error "Docker is installed but not running."
    exit 1
}


Write-Host "`n[1/2] Building CICFlowMeter (FIXED) image..." -ForegroundColor Yellow

docker build `
    -t cicflowmeter `
    -f integration/tools/CICFlowMeter/Dockerfile `
    integration/tools/CICFlowMeter

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build cicflowmeter image."
    exit 1
}

Write-Host "$([char]0x2714) cicflowmeter image built successfully." -ForegroundColor Green
Write-Host ""

Write-Host "`n[2/2] Building multi-layer-spoof-detector image..." -ForegroundColor Yellow

docker build `
    -t multi-layer-spoof-detector `
    -f integration/docker/Dockerfile `
    .

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to build multi-layer-spoof-detector image."
    exit 1
}

Write-Host "$([char]0x2714) multi-layer-spoof-detector image built successfully." -ForegroundColor Green
Write-Host ""

Write-Host "$([char]0x2714) All Docker images built successfully!" -ForegroundColor Green