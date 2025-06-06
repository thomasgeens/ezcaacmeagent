# ACME Agent Docker Cheat Sheet

## Building Images

```powershell
# Build with default settings
make build

# Build with specific version
VERSION=1.0.0 make build-version

# Build with environment variable overrides
AA_AuthenticationType=ServicePrincipalSecret make build
```

## Running Containers

```powershell
# Run with default settings
make run

# Run with specific auth method
make run-identity
make run-interactive
make run-devicecode
make run-spsecret
make run-spcert
make run-spcertbase64

# Run with environment variable overrides
AA_CertificateSubjectName=acme.example.com make run
AA_ClientId=my-client-id AA_ClientSecret=my-secret make run-spsecret

# Run with PowerShell shell
make run-shell
```

## Direct Docker Commands

```powershell
# Run with environment variables
docker run -d --name acme-agent -p 443:443 `
  -e AA_TenantId=my-tenant-id `
  -e AA_CertificateSubjectName=acme.example.com `
  -e AA_AuthenticationType=Identity `
  thomasgeens/ezcaacmeagent:2022

# Run with env file and overrides
docker run -d --name acme-agent -p 443:443 `
  --env-file env.spsecret.list `
  -e AA_ClientId=override-id `
  -e AA_ClientSecret=override-secret `
  thomasgeens/ezcaacmeagent:2022
```

# Run with env file and overrides and start an interactive powershell session
docker run --rm -it --name acme-agent -p 443:443 `
  --env-file env.list `
  --entrypoint powershell.exe `
  thomasgeens/ezcaacmeagent:2022
```

## Environment Variable Reference

| Variable | Description | Example |
|----------|-------------|---------|
| AA_TenantId | Azure AD tenant ID | 00000000-0000-0000-0000-000000000000 |
| AA_CAFriendlyName | Friendly name of the CA | My Issuing CA |
| AA_CertificateSubjectName | Subject name for the certificate | acme.example.com |
| AA_AuthenticationType | Authentication type | Identity, ServicePrincipalSecret |
| AA_FriendlyName | Friendly name for the agent | my-acme-agent |
| AA_AutomaticHealthChecks | Enable health checks | true, false |
| AA_ClientId | Service principal client ID | 00000000-0000-0000-0000-000000000000 |
| AA_ClientSecret | Service principal client secret | your-secret |
| AA_CertificateThumbprint | Certificate thumbprint | 1234567890ABCDEF1234567890ABCDEF12345678 |
