# Example of running Docker container directly with environment variables
# This shows how to use the AA_ environment variables directly with Docker

# Define variables
$imageName = "thomasgeens/ezcaacmeagent"
$imageTag = "2022"

# Example 1: Run with direct environment variables (no env file)
Write-Host "Example 1: Run Docker directly with environment variables" -ForegroundColor Green
Write-Host "docker run -d --name acme-direct -p 443:443 `
    -e AA_Verbose=true `
    -e AA_TenantId=00000000-aaaa-bbbb-cccc-000000000000 `
    -e AA_CAFriendlyName='My Issuing Intermediate SSL CA' `
    -e AA_CertificateSubjectName=acme-direct.example.com `
    -e AA_AuthenticationType=Identity `
    -e AA_FriendlyName=acme-direct `
    -e AA_AutomaticHealthChecks=true `
    -e AA_DNSServers=8.8.8.8,8.8.4.4 `
    $imageName`:$imageTag" -ForegroundColor Yellow
Write-Host ""

# Example 2: Combine env-file with additional environment variables
Write-Host "Example 2: Combine env-file with additional environment variables" -ForegroundColor Green
Write-Host "docker run -d --name acme-combined -p 443:443 `
    --env-file env.spsecret.list `
    -e AA_ClientId=override-client-id `
    -e AA_ClientSecret=override-client-secret `
    -e AA_CertificateSubjectName=combined.example.com `
    $imageName`:$imageTag" -ForegroundColor Yellow
Write-Host ""

# Example 3: Multi-stage approach - generate custom env file then use it
Write-Host "Example 3: Create custom environment file then use it" -ForegroundColor Green
Write-Host "# First, create custom env file using the Makefile:" -ForegroundColor Yellow
Write-Host "AA_ClientId=custom-id AA_ClientSecret=custom-secret OUTPUT_ENV_FILE=my-env.list ENV_FILE=env.spsecret.list make generate-env-file" -ForegroundColor Yellow
Write-Host "# Then run Docker with the custom env file:" -ForegroundColor Yellow
Write-Host "docker run -d --name acme-custom -p 443:443 --env-file my-env.list $imageName`:$imageTag" -ForegroundColor Yellow
Write-Host ""

# Example 4: Use PowerShell environment variables with Docker
Write-Host "Example 4: Set PowerShell environment variables and use with Docker" -ForegroundColor Green
Write-Host '$env:AA_CertificateSubjectName = "powershell.example.com"' -ForegroundColor Yellow
Write-Host '$env:AA_TenantId = "00000000-aaaa-bbbb-cccc-000000000000"' -ForegroundColor Yellow
Write-Host '$env:AA_AuthenticationType = "Identity"' -ForegroundColor Yellow
Write-Host "" 
Write-Host "docker run -d --name acme-ps -p 443:443 `
    -e AA_CertificateSubjectName=`$env:AA_CertificateSubjectName `
    -e AA_TenantId=`$env:AA_TenantId `
    -e AA_AuthenticationType=`$env:AA_AuthenticationType `
    $imageName`:$imageTag" -ForegroundColor Yellow

Write-Host ""
Write-Host "Note: These examples show multiple ways to set environment variables with Docker." -ForegroundColor Cyan
Write-Host "You can pick the approach that best fits your workflow." -ForegroundColor Cyan
