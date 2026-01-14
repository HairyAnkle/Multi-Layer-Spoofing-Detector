#!/usr/bin/env bash
set -e

echo "============================================"
echo " Docker Build Script - Multi-Layer Spoofing Detection System "
echo "============================================"
echo

# Ensure Docker exists
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed or not in PATH."
    exit 1
fi

# Ensure Docker daemon is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is installed but not running."
    exit 1
fi

# Build FIXED CICFlowMeter
echo "[1/2] Building CICFlowMeter (FIXED)..."

docker build \
    -t cicflowmeter \
    -f integration/tools/CICFlowMeter/Dockerfile \
    integration/tools/CICFlowMeter

echo "✔ cicflowmeter image built successfully."
echo

# Build multi-layer-spoof-detector
echo "[2/2] Building multi-layer-spoof-detector..."

docker build \
    -t multi-layer-spoof-detector \
    -f integration/docker/Dockerfile \
    ..

echo
echo "✔ All Docker images built successfully!"
