# Environment Variable Overrides with Direct Docker Commands
# This script demonstrates how to use environment variable overrides with Docker directly,
# without using the Makefile or helper script

# Set working directory to the project root (parent of examples folder)
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Split-Path -Parent $scriptPath)

# Example 1: Set environment variables in PowerShell and pass them to Docker
Write-Host "Example 1: Setting environment variables in PowerShell and using Docker run" -ForegroundColor Green
Write-Host "Setting environment variables..." -ForegroundColor Yellow
$env:AA_TenantId = "custom-tenant-id"
$env:AA_CertificateSubjectName = "direct-powershell.example.com"
$env:AA_FriendlyName = "Direct PowerShell Example"

Write-Host "Environment variables set:" -ForegroundColor Yellow
Write-Host "  AA_TenantId = $($env:AA_TenantId)" -ForegroundColor Cyan
Write-Host "  AA_CertificateSubjectName = $($env:AA_CertificateSubjectName)" -ForegroundColor Cyan
Write-Host "  AA_FriendlyName = $($env:AA_FriendlyName)" -ForegroundColor Cyan

Write-Host "Docker command to run:" -ForegroundColor Yellow
$dockerCmd1 = "docker run -d --name acme-direct-env --env-file env.identity.list --env AA_TenantId --env AA_CertificateSubjectName --env AA_FriendlyName -p 443:443 thomasgeens/ezcaacmeagent:2022"
Write-Host $dockerCmd1 -ForegroundColor Cyan
Write-Host ""
Write-Host "This approach passes the environment variables from the current PowerShell session to Docker." -ForegroundColor Magenta
Write-Host "Note: For this to work, the environment variables must be present in the current session." -ForegroundColor Magenta
Write-Host ""

# Example 2: Pass environment variables directly to Docker
Write-Host "Example 2: Passing environment variables directly to Docker run" -ForegroundColor Green
$dockerCmd2 = @"
docker run -d --name acme-direct-args --env-file env.spsecret.list `
  -e AA_ClientId="your-client-id" `
  -e AA_ClientSecret="your-client-secret" `
  -e AA_CertificateSubjectName="direct-args.example.com" `
  -p 443:443 thomasgeens/ezcaacmeagent:2022
"@
Write-Host $dockerCmd2 -ForegroundColor Cyan
Write-Host ""
Write-Host "This approach hardcodes the environment variables in the Docker run command." -ForegroundColor Magenta
Write-Host "You'll need to replace placeholder values with your actual values." -ForegroundColor Magenta
Write-Host ""

# Example 3: Create an environment file and then run Docker
Write-Host "Example 3: Creating a custom environment file and then running Docker" -ForegroundColor Green
$customEnvFile = "env.custom.list"
Write-Host "Creating custom environment file $customEnvFile..." -ForegroundColor Yellow
Copy-Item -Path "env.spsecret.list" -Destination $customEnvFile -Force

# Add/replace environment variables in the custom file
Write-Host "Modifying environment variables in $customEnvFile..." -ForegroundColor Yellow
$envVars = @{
    "AA_ClientId" = "file-client-id"
    "AA_ClientSecret" = "file-client-secret"
    "AA_CertificateSubjectName" = "custom-file.example.com"
    "AA_FriendlyName" = "Custom File Example"
}

foreach ($key in $envVars.Keys) {
    $pattern = "^$key="
    $newValue = "$key=$($envVars[$key])"
    $content = Get-Content $customEnvFile
    
    if ($content | Select-String -Pattern $pattern -Quiet) {
        # Replace existing value
        $content = $content -replace $pattern, $newValue
        $content | Set-Content $customEnvFile
    } else {
        # Add new variable
        Add-Content -Path $customEnvFile -Value $newValue
    }
}

Write-Host "Custom environment file created with these overrides:" -ForegroundColor Yellow
foreach ($key in $envVars.Keys) {
    Write-Host "  $key = $($envVars[$key])" -ForegroundColor Cyan
}

Write-Host "Docker command to run:" -ForegroundColor Yellow
$dockerCmd3 = "docker run -d --name acme-custom-file --env-file $customEnvFile -p 443:443 thomasgeens/ezcaacmeagent:2022"
Write-Host $dockerCmd3 -ForegroundColor Cyan
Write-Host ""
Write-Host "This approach creates a custom environment file with your settings." -ForegroundColor Magenta
Write-Host "The advantage is that you can reuse this file multiple times." -ForegroundColor Magenta
Write-Host ""

# Example 4: Combining environment file with additional overrides
Write-Host "Example 4: Combining environment file with additional overrides" -ForegroundColor Green
$dockerCmd4 = @"
docker run -d --name acme-combined --env-file env.identity.list `
  -e AA_TenantId="combined-tenant-id" `
  -e AA_CertificateSubjectName="combined.example.com" `
  -p 443:443 thomasgeens/ezcaacmeagent:2022
"@
Write-Host $dockerCmd4 -ForegroundColor Cyan
Write-Host ""
Write-Host "This approach uses a base environment file but overrides specific variables." -ForegroundColor Magenta
Write-Host "Docker prioritizes the -e parameters over the values in the env file." -ForegroundColor Magenta
Write-Host ""

Write-Host "Clean Up:" -ForegroundColor Green
Write-Host "To clean up the custom environment file:" -ForegroundColor Yellow
Write-Host "Remove-Item $customEnvFile" -ForegroundColor Cyan
Write-Host ""
Write-Host "To clean up the environment variables set in this session:" -ForegroundColor Yellow
Write-Host "Remove-Item env:AA_TenantId" -ForegroundColor Cyan
Write-Host "Remove-Item env:AA_CertificateSubjectName" -ForegroundColor Cyan
Write-Host "Remove-Item env:AA_FriendlyName" -ForegroundColor Cyan

# Clean up session environment variables
Remove-Item env:AA_TenantId -ErrorAction SilentlyContinue
Remove-Item env:AA_CertificateSubjectName -ErrorAction SilentlyContinue
Remove-Item env:AA_FriendlyName -ErrorAction SilentlyContinue
