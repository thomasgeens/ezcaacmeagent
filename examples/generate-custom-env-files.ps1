# Example script demonstrating how to generate custom environment files
# This script shows how to create customized environment files from base templates

# Function to generate a custom environment file
function New-CustomEnvFile {
    param (
        [string]$BaseEnvFile,
        [string]$OutputFile,
        [hashtable]$EnvVars
    )
    
    Write-Host "Generating custom environment file: $OutputFile based on $BaseEnvFile" -ForegroundColor Green
    
    # Convert hashtable to environment variable assignments
    $envVarsString = ($EnvVars.GetEnumerator() | ForEach-Object { 
        # Set the environment variables
        Set-Item -Path "env:$($_.Key)" -Value $_.Value
        # Return the key for display
        "$($_.Key)=$($_.Value)"
    }) -join " "
    
    # Generate the make command
    $makeCommand = "OUTPUT_ENV_FILE='$OutputFile' ENV_FILE='$BaseEnvFile' make generate-env-file"
    
    Write-Host $envVarsString $makeCommand -ForegroundColor Yellow
    Write-Host ""
    
    # Uncomment to actually run the command
    # Invoke-Expression "pwsh -Command `"$makeCommand`""
    
    # Clean up environment variables
    foreach ($key in $EnvVars.Keys) {
        Remove-Item -Path "env:$key" -ErrorAction SilentlyContinue
    }
}

# Example 1: Create a customized service principal secret configuration
New-CustomEnvFile -BaseEnvFile "env.spsecret.list" -OutputFile "custom-spsecret.env.list" -EnvVars @{
    "AA_ClientId" = "00000000-1111-2222-3333-444444444444"
    "AA_ClientSecret" = "MySuperSecretClientSecret"
    "AA_TenantId" = "8dbee730-1234-5678-9abc-085d4a3630c1"
    "AA_CertificateSubjectName" = "custom-sp.example.com"
    "AA_FriendlyName" = "custom-sp-instance"
}

# Example 2: Create a customized certificate-based configuration
New-CustomEnvFile -BaseEnvFile "env.spcert.list" -OutputFile "custom-spcert.env.list" -EnvVars @{
    "AA_ClientId" = "00000000-5555-6666-7777-888888888888"
    "AA_CertificateThumbprint" = "1234567890ABCDEF1234567890ABCDEF12345678"
    "AA_TenantId" = "8dbee730-1234-5678-9abc-085d4a3630c1"
    "AA_CertificateSubjectName" = "custom-cert.example.com"
    "AA_DNSServers" = "1.1.1.1,1.0.0.1"
}

# Example 3: Create a customized identity configuration
New-CustomEnvFile -BaseEnvFile "env.identity.list" -OutputFile "custom-identity.env.list" -EnvVars @{
    "AA_TenantId" = "8dbee730-1234-5678-9abc-085d4a3630c1"
    "AA_CertificateSubjectName" = "custom-identity.example.com"
    "AA_FriendlyName" = "custom-identity-instance"
    "AA_AutomaticHealthChecks" = "false"
}

Write-Host "To generate these custom environment files, uncomment the Invoke-Expression lines in this script." -ForegroundColor Cyan
Write-Host "After generating the files, you can use them with:" -ForegroundColor Cyan
Write-Host "ENV_FILE=custom-spsecret.env.list make run" -ForegroundColor Yellow
