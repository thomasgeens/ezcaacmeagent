# Example script demonstrating environment variable overrides
# This script shows various ways to override environment variables when running
# the ACME Agent Docker container

# Basic run with default env.list but override certificate subject name
Write-Host "Example 1: Basic run with certificate subject name override" -ForegroundColor Green
Write-Host "AA_CertificateSubjectName=custom.example.com make run" -ForegroundColor Yellow
Write-Host ""

# Run with Service Principal Secret authentication but override client credentials
Write-Host "Example 2: Service Principal Secret with credential override" -ForegroundColor Green
Write-Host "AA_ClientId=override-client-id AA_ClientSecret=override-secret make run-spsecret" -ForegroundColor Yellow
Write-Host ""

# Run with Identity authentication but override tenant ID and DNS settings
Write-Host "Example 3: Identity auth with tenant and DNS overrides" -ForegroundColor Green
Write-Host "AA_TenantId=new-tenant-id AA_DNSServers=1.1.1.1,1.0.0.1 make run-identity" -ForegroundColor Yellow
Write-Host ""

# Multiple overrides in a single command
Write-Host "Example 4: Multiple overrides in a single command" -ForegroundColor Green
Write-Host "AA_TenantId=tenant-id AA_FriendlyName=custom-agent AA_CertificateSubjectName=multiple.example.com AA_AutomaticHealthChecks=false make run" -ForegroundColor Yellow
Write-Host ""

# You can uncomment and run any of these examples directly
# For PowerShell, you can set environment variables like this:
Write-Host "To run these examples in PowerShell:" -ForegroundColor Cyan
Write-Host '$env:AA_CertificateSubjectName = "custom.example.com"; pwsh -Command "make run"' -ForegroundColor Yellow
Write-Host ""
Write-Host "Or for multiple variables:" -ForegroundColor Cyan
Write-Host '$env:AA_ClientId = "override-client-id"; $env:AA_ClientSecret = "override-secret"; pwsh -Command "make run-spsecret"' -ForegroundColor Yellow
