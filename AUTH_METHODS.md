# ezcaACMEAgent - Authentication Methods Guide

This document provides instructions on how to use different authentication methods with the KEYTOS ACME Agent Docker container.

## Available Authentication Methods

The KEYTOS ACME Agent supports the following authentication methods:

1. **Identity** - Uses the managed identity of the system
2. **Interactive** - Uses interactive authentication flow
3. **UseDeviceCode** - Uses device code authentication flow
4. **ServicePrincipalSecret** - Uses service principal with client ID and secret
5. **ServicePrincipalCertificate** - Uses service principal with client ID and certificate

## Environment Files

We provide example environment files for each authentication method:

- `env.list` - Default configuration (DeviceCode auth)
- `env.identity.list` - Using managed identity auth
- `env.interactive.list` - Using interactive auth
- `env.devicecode.list` - Using device code auth
- `env.spsecret.list` - Using service principal with secret
- `env.spcert.list` - Using service principal with certificate thumbprint
- `env.spcertbase64.list` - Using service principal with base64-encoded certificate

## Using the Makefile

The Makefile provides convenient targets for building and running the container with different authentication methods.

### Building the Container

```powershell
# Build with default settings
make build

# Build with specific version
make VERSION=1.0.0 build-version
```

### Running with Different Authentication Methods

```powershell
# Run with default settings (using env.list)
make run

# Run with managed identity authentication
make run-identity

# Run with interactive authentication
make run-interactive

# Run with device code authentication
make run-devicecode

# Run with service principal secret authentication
make run-spsecret

# Run with service principal certificate (thumbprint) authentication
make run-spcert

# Run with service principal certificate (base64) authentication
make run-spcertbase64
```

## Environment Variable Overrides

You can override any environment variable by directly setting AA_ prefixed environment variables when running Makefile targets.

### Basic Usage

```powershell
# Override environment variables with any run target
AA_TenantId=my-tenant-id AA_FriendlyName=custom-name make run

# Override environment variables with specialized run targets
AA_ClientId=new-client-id AA_ClientSecret=new-secret make run-spsecret
```

### Build-Time Overrides

You can also override build arguments during image building:

```powershell
# Override build-time arguments
AA_DefaultConfig=custom-config make build

# Override both build version and build arguments
VERSION=1.0.0 AA_DefaultConfig=custom-config make build-version
```

### Generating Custom Environment Files

You can create custom environment files that combine a base configuration with your overrides:

```powershell
# Generate a custom environment file based on the service principal secret config
OUTPUT_ENV_FILE=my-custom-sp.list ENV_FILE=env.spsecret.list AA_ClientId=my-client-id AA_ClientSecret=my-secret make generate-env-file

# Then use the custom environment file
ENV_FILE=my-custom-sp.list make run
```

### Common Override Scenarios

1. **Change the certificate subject name**:
   ```powershell
   AA_CertificateSubjectName=new-hostname.example.com make run-spcert
   ```

2. **Change tenant ID and DNS settings**:
   ```powershell
   AA_TenantId=different-tenant AA_DNSServers=1.1.1.1,1.0.0.1 make run-identity
   ```

3. **Override service principal credentials**:
   ```powershell
   AA_ClientId=new-id AA_ClientSecret=new-secret make run-spsecret
   ```

### Multiple Overrides

You can specify multiple environment variable overrides in a single command:

```powershell
AA_TenantId=tenant-id AA_FriendlyName=name AA_CertificateSubjectName=hostname.example.com AA_DNSServers=8.8.8.8,8.8.4.4 make run
```

### Running with PowerShell Shell

You can also run the container with a PowerShell shell for debugging or manual operations:

```powershell
# Run with default settings (using env.list)
pwsh -Command "make run-shell"

# Run with a specific environment file
pwsh -Command "make ENV_FILE=env.spcert.list run-shell"
```

## Important Notes for Service Principal Authentication

### Service Principal with Secret

When using the `ServicePrincipalSecret` authentication method, you need to:

1. Create a service principal in Azure AD
2. Grant it appropriate permissions
3. Set the `AA_ClientId` and `AA_ClientSecret` variables in your environment file

### Service Principal with Certificate

When using the `ServicePrincipalCertificate` authentication method, you have two options:

1. **Using a certificate thumbprint**:
   - Install the certificate in the container's certificate store
   - Set the `AA_ClientId` and `AA_CertificateThumbprint` variables

2. **Using a base64-encoded certificate**:
   - Set the `AA_ClientId` and `AA_CertificateBase64` variables
   - Note: In a real environment, you would need to convert the certificate to SecureString in the container

### Creating a Test Certificate

For testing purposes, you can create a self-signed certificate:

```powershell
# Create a self-signed certificate
$cert = New-SelfSignedCertificate -CertStoreLocation "Cert:\CurrentUser\My" -Subject "CN=ACMEAgentTest" -KeySpec KeyExchange

# Export the certificate with private key to PFX
$certPassword = ConvertTo-SecureString -String "Password123!" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath ".\ACMEAgentTest.pfx" -Password $certPassword

# Export the certificate to PEM format
Export-Certificate -Cert $cert -FilePath ".\ACMEAgentTest.cer" -Type CERT
```

## Customizing Environment Files

You can create your own environment files by copying one of the examples and modifying it to suit your needs:

```powershell
# Create a custom environment file
Copy-Item -Path .\env.spcert.list -Destination .\env.custom.list

# Edit the file with your specific values
notepad .\env.custom.list

# Run the container with your custom file
pwsh -Command "make ENV_FILE=env.custom.list run"
```

## Using Direct Docker Commands

You can also use Docker commands directly without the Makefile:

```powershell
# Run with environment file
docker run -d --name acme-agent -p 443:443 --env-file env.list keytos/acmeagent

# Run with environment variables directly
docker run -d --name acme-agent -p 443:443 \
  -e AA_TenantId=your-tenant-id \
  -e AA_AuthenticationType=Identity \
  -e AA_CertificateSubjectName=custom.example.com \
  keytos/acmeagent

# Run with service principal authentication
docker run -d --name acme-agent-sp -p 444:443 \
  -e AA_TenantId=your-tenant-id \
  -e AA_AuthenticationType=ServicePrincipalSecret \
  -e AA_ClientId=your-client-id \
  -e AA_ClientSecret=your-client-secret \
  -e AA_CertificateSubjectName=custom.example.com \
  keytos/acmeagent
```
