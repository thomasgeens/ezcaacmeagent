# Direct Docker Command Examples for ACME Agent
# This script demonstrates how to use Docker commands directly without the Makefile
# to run ACME Agent containers with different authentication methods

# Set working directory to the project root (parent of examples folder)
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent $scriptPath)

# Example 1: Run with default settings (device code auth)
Write-Host "Example 1: Run with default settings (device code auth)" -ForegroundColor Green
Write-Host "docker run -d --name acme-devicecode -p 443:443 --env-file env.list thomasgeens/ezcaacmeagent:2022" -ForegroundColor Yellow
Write-Host ""

# Example 2: Run with managed identity authentication
Write-Host "Example 2: Run with managed identity authentication" -ForegroundColor Green
Write-Host "docker run -d --name acme-identity -p 443:443 --env-file env.identity.list thomasgeens/ezcaacmeagent:2022" -ForegroundColor Yellow
Write-Host ""

# Example 3: Run with service principal secret auth and environment variable overrides
Write-Host "Example 3: Run with service principal secret auth and environment variable overrides" -ForegroundColor Green
Write-Host 'docker run -d --name acme-spsecret -p 443:443 --env-file env.spsecret.list -e AA_ClientId="your-client-id" -e AA_ClientSecret="your-client-secret" -e AA_CertificateSubjectName="custom.example.com" thomasgeens/ezcaacmeagent:2022' -ForegroundColor Yellow
Write-Host ""

# Example 4: Run with service principal certificate auth (thumbprint)
Write-Host "Example 4: Run with service principal certificate auth (thumbprint)" -ForegroundColor Green
Write-Host 'docker run -d --name acme-spcert -p 443:443 --env-file env.spcert.list -e AA_ClientId="your-client-id" -e AA_CertificateThumbprint="your-thumbprint" thomasgeens/ezcaacmeagent:2022' -ForegroundColor Yellow
Write-Host ""

# Example 5: Run interactive PowerShell shell in the container
Write-Host "Example 5: Run interactive PowerShell shell in the container" -ForegroundColor Green
Write-Host "docker run -it --rm --name acme-shell --entrypoint powershell.exe --env-file env.list thomasgeens/ezcaacmeagent:2022" -ForegroundColor Yellow
Write-Host ""

# Example 6: Run with all environment variables defined directly (no env file)
Write-Host "Example 6: Run with all environment variables defined directly (no env file)" -ForegroundColor Green
$dockerCommand = @"
docker run -d --name acme-custom -p 443:443 `
  -e AA_TenantId="your-tenant-id" `
  -e AA_AuthenticationType="ServicePrincipalSecret" `
  -e AA_ClientId="your-client-id" `
  -e AA_ClientSecret="your-client-secret" `
  -e AA_CertificateSubjectName="acme.example.com" `
  -e AA_FriendlyName="Direct Docker Example" `
  -e AA_DNSServers="8.8.8.8,8.8.4.4" `
  -e AA_AutomaticHealthChecks="true" `
  thomasgeens/ezcaacmeagent:2022
"@
Write-Host $dockerCommand -ForegroundColor Yellow
Write-Host ""

Write-Host "To execute any of these examples, copy the command and run it in your PowerShell terminal." -ForegroundColor Cyan
Write-Host "You'll need to replace placeholder values like 'your-client-id' with your actual values." -ForegroundColor Cyan
Write-Host ""
Write-Host "After running a container, you can check its status with:" -ForegroundColor Cyan
Write-Host "docker ps" -ForegroundColor Yellow
Write-Host ""
Write-Host "And view its logs with:" -ForegroundColor Cyan
Write-Host "docker logs <container-name>" -ForegroundColor Yellow
Write-Host ""
Write-Host "To stop and remove a container:" -ForegroundColor Cyan
Write-Host "docker stop <container-name> && docker rm <container-name>" -ForegroundColor Yellow
