# Example script demonstrating build-time environment variable overrides
# This script shows how to customize Docker image builds with environment variables

# Basic build with overrides
Write-Host "Example 1: Basic build with environment variable overrides" -ForegroundColor Green
Write-Host "AA_DefaultConfig=production AA_DNSServers=1.1.1.1,1.0.0.1 make build" -ForegroundColor Yellow
Write-Host ""

# Build specific version with overrides
Write-Host "Example 2: Build specific version with environment variable overrides" -ForegroundColor Green
Write-Host "VERSION=1.0.0 AA_DefaultConfig=production AA_DNSServers=1.1.1.1,1.0.0.1 make build-version" -ForegroundColor Yellow
Write-Host ""

# Build with custom image name and overrides
Write-Host "Example 3: Build with custom image name and environment variable overrides" -ForegroundColor Green
Write-Host "IMAGE_NAME=mycompany/acmeagent IMAGE_TAG=latest AA_DefaultConfig=custom make build" -ForegroundColor Yellow
Write-Host ""

# Build with multiple custom variables
Write-Host "Example 4: Build with multiple custom environment variables" -ForegroundColor Green
Write-Host "AA_DefaultConfig=production AA_DNSServers=1.1.1.1,1.0.0.1 AA_AutomaticHealthChecks=true AA_FriendlyName=production-agent make build" -ForegroundColor Yellow
Write-Host ""

# For PowerShell, you can set environment variables like this:
Write-Host "To run these examples in PowerShell:" -ForegroundColor Cyan
Write-Host '$env:AA_DefaultConfig = "production"; $env:AA_DNSServers = "1.1.1.1,1.0.0.1"; pwsh -Command "make build"' -ForegroundColor Yellow
