# ezcaacmeagent
KEYTOS EZCA ACME Agent on Windows Server Core 2022 LTSC

## Overview

This repository contains Docker configuration for containerizing the KEYTOS ACME Agent with various authentication methods, as well as a PowerShell script for deploying ACME Agent instances (`New-KEYTOSACMEAgentInstance.ps1`).

## Features

- Multiple authentication methods:
  - Managed Identity
  - Interactive
  - Device Code
  - Service Principal with Secret
  - Service Principal with Certificate (Thumbprint or Base64)
- Docker container with preconfigured environments
- Makefile for simple building and running
- Environment variable override capability

## Quick Start

### Using the Makefile

```powershell
# Build the Docker image
make build

# Run with device code authentication
make run-devicecode

# Run with service principal secret authentication
make run-spsecret
```

### Using Direct Docker Commands

You can also use Docker commands directly:

```powershell
# Run with environment variable overrides
docker run --env-file env.list --env AA_CertificateSubjectName=custom.example.com -d keytos/acmeagent

# Run with service principal authentication
docker run --env-file env.spsecret.list --env AA_ClientId=your-client-id --env AA_ClientSecret=your-secret -d keytos/acmeagent
```

### Overriding Environment Variables

You can override any environment variable by setting AA_ prefixed environment variables:

```powershell
# Override certificate subject name
AA_CertificateSubjectName=custom.example.com make run

# Override multiple variables
AA_ClientId=new-id AA_ClientSecret=new-secret make run-spsecret
```

## Documentation

- [Authentication Methods](AUTH_METHODS.md) - Detailed guide on authentication methods and usage
- [Environment Variable Overrides](ENV_VAR_OVERRIDES.md) - Guide on using environment variables
- [Examples](examples/) - Example scripts for various scenarios

## Requirements

- Docker Desktop or Docker Engine
- PowerShell 7+ (recommended)
- Make (for using the Makefile)
