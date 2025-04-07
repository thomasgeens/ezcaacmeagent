# escape=`

# Dockerfile for KEYTOS EZCA ACME Agent on Windows Server Core 2022 LTSC
# This Dockerfile builds a container image for the KEYTOS EZCA ACME Agent on Windows Server Core 2022 LTSC.
# It installs the necessary dependencies, downloads the EZCA ACME Agent, and sets up the environment for running the agent.
# The container image is based on the Windows Server Core 2022 LTSC image with .NET Framework 4.8 and ASP.NET Core Hosting Bundle installed.
# Base image: mcr.microsoft.com/dotnet/framework/aspnet:4.8.1-20250114-windowsservercore-ltsc2022
FROM mcr.microsoft.com/dotnet/framework/aspnet@sha256:3e3746642401c155effabe3b156ef21d166a3ae9046bf584e337e60f49b51a68
LABEL maintainer="Thomas Geens <thomas@geens.be>"

# Build-time arguments
ARG BUILD_DATE # Date and time on which the image was built, conforming to RFC 3339.
ARG BUILD_VERSION # Version of the packaged software.
ARG VCS_REF # Source control revision identifier for the packaged software.
ARG Verbose="true" # Switch to enable or disable verbose logging. Default is `$true`.
ARG Debug="false" # Switch to enable or disable debug logging. Default is `$false`.
ARG TenantId="8dbee730-91af-4ab0-9fb6-085d4a3630c1" # The tenant ID of the Azure AD tenant. Can be in the form of `tenant.onmicrosoft.com` or the GUID.
ARG CAFriendlyName="" # The friendly name of the Issuing Intermediate SSL CA to be selected from the Issuing CA list. If omitted, the first CA in the list will be selected.
ARG CertificateSubjectName # The subject name for the authentication certificate that will be used to authenticate with EZCA.
ARG AuthenticationType="Identity" # The authentication type to be used. Can be one of the following `Identity`, `UseDeviceCode` or `Interactive`. Default is `Identity`.
ARG FriendlyName="" # The friendly name of the ACME agent instance. If omitted, it will be set to the Certificate Subject Name.
ARG AutomaticHealthChecks="false" # Switch to activate the EZCA managed health checks of the ACME Agent instance. Default is $false.
ARG URL # The URL of the ACME Agent instance. If omitted, it will be set to `https://{CertificateSubjectName}`.
ARG WebDeployDownloadURL="https://download.microsoft.com/download/b/d/8/bd882ec4-12e0-481a-9b32-0fae8e3c0b78/webdeploy_amd64_en-US.msi" # The URL to download the WebDeploy MSI installer. Default is `https://download.microsoft.com/download/b/d/8/bd882ec4-12e0-481a-9b32-0fae8e3c0b78/webdeploy_amd64_en-US.msi`.
ARG ASPNetCoreRuntimeDownloadURL="https://aka.ms/dotnet/9.0/daily/dotnet-hosting-win.exe" # The URL to download the ASP.NET Core Runtime installer. Default is `https://aka.ms/dotnet/9.0/daily/dotnet-hosting-win.exe`. Updated links can be found at `https://github.com/dotnet/aspnetcore`.
ARG ServiceMonitorDownloadURL="https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.10/ServiceMonitor.exe" # The URL to download the Service Monitor executable. Default is `https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.10/ServiceMonitor.exe`. Updated links can be found at `https://github.com/microsoft/IIS.ServiceMonitor`.
ARG AppInsightsEndpoint="" # The endpoint of the Application Insights instance.
ARG ACMEAgentDownloadURL="https://download.keytos.io/Downloads/EZCAACME/ACMEAgent.zip" # The URL to download the ACME Agent ZIP file. Default is `https://download.keytos.io/Downloads/EZCAACME/ACMEAgent.zip`.
ARG AutoReplace="false" # Switch to enable or disable the automatic replacement of an existing ACME Agent instance. Default is $false.
ARG NuGet_MinimumVersion="2.8.5.201" # The version of the NuGet package provider to be installed. Default is `2.8.5.201`.
ARG NuGet_MaximumVersion="2.8.5.999" # The maximum version of the NuGet package provider to be installed. Default is `2.8.5.999`.
ARG Az_Accounts_MinimumVersion="4.0.2" # The minimum version of the Az.Accounts module to be installed. Default is `4.0.2`.
ARG Az_Accounts_MaximumVersion="4.0.99999" # The maximum version of the Az.Accounts module to be installed. Default is `4.0.2`.
ARG Stages="Deploy, Cleanup, HealthCheck, ServiceMonitor" # Stages to run: `Build`, `Deploy`, `Cleanup`, `HealthCheck`, `ServiceMonitor`. Default is all stages `Build, Deploy, Cleanup, HealthCheck, ServiceMonitor`.

# Expose the ports for the ACME Agent instance
EXPOSE 443

# Set the labels for the container image
# The version of the Open Container Initiative (OCI) image format specification that the image conforms to.
LABEL org.label-schema.schema-version="1.0"
LABEL org.label-schema.docker.cmd="docker build --build-arg BUILD_DATE=$BUILD_DATE --build-arg BUILD_VERSION=$BUILD_VERSION --build-arg VCS_REF=$VCS_REF -t thomasgeens/ezcaacmeagent:latest ."
LABEL org.label-schema.docker.cmd="docker run -d --name ezcaacmeagent -p 443:443 thomasgeens/ezcaacmeagent:latest"
# org.opencontainers.image.created date and time on which the image was built, conforming to RFC 3339.
# - The date and time MUST be in UTC and MUST be expressed in the format YYYY-MM-DDTHH:MM:SSZ
# - The date and time MAY be expressed in the format YYYY-MM-DDTHH:MM:SS+hh:mm or YYYY-MM-DDTHH:MM:SS-hh:mm
# Legacy labels: org.label-schema.build-date
LABEL org.opencontainers.image.created=${BUILD_DATE}
LABEL org.label-schema.build-date=${BUILD_DATE}
LABEL org.label-schema.release-date=${BUILD_DATE}
# org.opencontainers.image.authors contact details of the people or organization responsible for the image (freeform string)
LABEL org.opencontainers.image.authors="Thomas Geens <thomas@geens.be>"
LABEL org.label-schema.maintainer="Thomas Geens <thomas@geens.be>"
# org.opencontainers.image.url URL to find more information on the image (string)
LABEL org.opencontainers.image.url="https://www.keytos.io/docs/azure-pki/how-to-enable-acme-for-private-pki/"
# org.opencontainers.image.documentation URL to get documentation on the image (string)
LABEL org.opencontainers.image.documentation="https://www.keytos.io/docs/azure-pki/how-to-enable-acme-for-private-pki/"
LABEL org.label-schema.url="https://www.keytos.io/docs/azure-pki/how-to-enable-acme-for-private-pki/"
# org.opencontainers.image.source URL to get source code for building the image (string)
LABEL org.opencontainers.image.source="https://github.com/thomasgeens/ezcaacmeagent/blob/main/Dockerfile"
# org.label-schema.vcs-url URL to get support for the image (string)
LABEL org.label-schema.vcs-url="https://github.com/thomasgeens/ezcaacmeagent/blob/main/README.md"
# org.opencontainers.image.version version of the packaged software
# - The version MAY match a LABEL org.label-schema.or tag in the source code repository
# - version MAY be Semantic versioning-compatible
LABEL org.opencontainers.image.version=${BUILD_VERSION}
LABEL org.label-schema.version=${BUILD_VERSION}
# org.opencontainers.image.revision Source control revision identifier for the packaged software.
LABEL org.opencontainers.image.revision=${VCS_REF}
LABEL org.label-schema.revision=${VCS_REF}
# org.opencontainers.image.vendor Name of the distributing entity, organization or individual.
LABEL org.opencontainers.image.vendor="KEYTOS"
# org.label-schema.name Name of the image (string)
LABEL org.label-schema.name="thomasgeens/ezcaacmeagent"
# org.opencontainers.image.title Human-readable title of the image (string)
LABEL org.opencontainers.image.title="KEYTOS EZCA ACME Agent on Windows Server Core 2022 LTSC"
LABEL org.label-schema.description="KEYTOS EZCA ACME Agent on Windows Server Core 2022 LTSC"
# org.opencontainers.image.description Human-readable description of the software packaged in the image (string)
LABEL org.opencontainers.image.description="KEYTOS EZCA ACME Agent on Windows Server Core 2022 LTSC"
# org.opencontainers.image.base.digest Digest of the image this image is based on (string)
# This SHOULD be the immediate image sharing zero-indexed layers with the image, such as from a Dockerfile FROM statement.
# This SHOULD NOT reference any other images used to generate the contents of the image (e.g., multi-stage Dockerfile builds).
LABEL org.opencontainers.image.base.digest="sha256:3e3746642401c155effabe3b156ef21d166a3ae9046bf584e337e60f49b51a68"
# org.opencontainers.image.base.name Image reference of the image this image is based on (string)
LABEL org.opencontainers.image.base.name="mcr.microsoft.com/dotnet/framework/aspnet:4.8.1-20250114-windowsservercore-ltsc2022"
LABEL org.label-schema.os="Windows Server Core 2022 LTSC"
# [System.Environment]::OSVersion.Version
LABEL org.label-schema.os-version="10.0.26100.0"
LABEL org.label-schema.package="PowerShell"
# $PSVersionTable
LABEL org.label-schema.package-version="5.1.26100.2161"
LABEL org.label-schema.package="NuGet"
LABEL org.label-schema.package-version="${NuGet_MinimumVersion}"
LABEL org.label-schema.package="Az.Accounts"
LABEL org.label-schema.package-version="${Az_Accounts_MinimumVersion}"
LABEL org.label-schema.package="IIS"
# Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\InetStp\\'
# Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\InetStp' | select InstallPath, VersionString, @{n="ProductVersion";e={(Get-ItemProperty ($_.InstallPath + "\w3wp.exe")).VersionInfo.ProductVersion}}
LABEL org.label-schema.package-version="10.0.26100.1882"
LABEL org.label-schema.package="ASP.Net Core Hosting Bundle"
# Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like 'Microsoft ASP.NET Core*' }
LABEL org.label-schema.package-version="9.0.4.25160"
LABEL org.label-schema.package="IIS.ServiceMonitor"
# (Get-Item 'C:\\ServiceMonitor.exe').VersionInfo
LABEL org.label-schema.package-version="2.0.1.04"
LABEL org.label-schema.package="KEYTOS EZCA ACME Agent"
# (Get-Item 'C:\\inetpub\\ezcaacmeroot\\ACMEAgent.exe').VersionInfo
LABEL org.label-schema.package-version="1.0.0.0"

# Set the environment variables
ENV `
AA_Verbose=${Verbose} `
AA_Debug=${Debug} `
AA_TenantId=${TenantId} `
AA_CAFriendlyName=${CAFriendlyName} `
AA_CertificateSubjectName=${CertificateSubjectName} `
AA_AuthenticationType=${AuthenticationType} `
AA_FriendlyName=${FriendlyName} `
AA_AutomaticHealthChecks=${AutomaticHealthChecks} `
AA_URL=${URL} `
AA_WebDeployDownloadURL=${WebDeployDownloadURL} `
AA_ASPNetCoreRuntimeDownloadURL=${ASPNetCoreRuntimeDownloadURL} `
AA_ServiceMonitorDownloadURL=${ServiceMonitorDownloadURL} `
AA_AppInsightsEndpoint=${AppInsightsEndpoint} `
AA_ACMEAgentDownloadURL=${ACMEAgentDownloadURL} `
AA_AutoReplace=${AutoReplace} `
AA_NuGet_MinimumVersion=${NuGet_MinimumVersion} `
AA_NuGet_MaximumVersion=${NuGet_MaximumVersion} `
AA_Az_Accounts_MinimumVersion=${Az_Accounts_MinimumVersion} `
AA_Az_Accounts_MaximumVersion=${Az_Accounts_MaximumVersion} `
AA_Stages=${Stages}

# Set the working directory
WORKDIR /

# Copy the PowerShell script to the container
COPY --link ./New-KEYTOSACMEAgentInstance.ps1 ./New-KEYTOSACMEAgentInstance.ps1

# Set the default shell to Windows PowerShell
SHELL ["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "-Command"]

# Build the container image by running the PowerShell script
# and passing the build-time arguments via environment variables as arguments to the script.
RUN "`
$DebugPreference = 'SilentlyContinue'; `
$VerbosePreference = 'Continue'; `
$ErrorActionPreference = 'Stop'; `
$ProgressPreference = 'SilentlyContinue'; `
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; `
. \New-KEYTOSACMEAgentInstance.ps1; `
New-KEYTOSACMEAgentInstance `
    -Verbose:($Env:AA_Verbose -eq [bool]::TrueString) `
    -Debug:($Env:AA_Debug -eq [bool]::TrueString) `
    -TenantId $Env:AA_TenantId `
    -CAFriendlyName $Env:AA_CAFriendlyName `
    -CertificateSubjectName 'dummy' `
    -AuthenticationType $Env:AA_AuthenticationType `
    -FriendlyName 'dummy' `
    -AutomaticHealthChecks:($Env:AA_AutomaticHealthChecks -eq [bool]::TrueString) `
    -URL 'dummy' `
    -WebDeployDownloadURL $Env:AA_WebDeployDownloadURL `
    -ASPNetCoreRuntimeDownloadURL $Env:AA_ASPNetCoreRuntimeDownloadURL `
    -ServiceMonitorDownloadURL $Env:AA_ServiceMonitorDownloadURL `
    -AppInsightsEndpoint $Env:AA_AppInsightsEndpoint `
    -ACMEAgentDownloadURL $Env:AA_ACMEAgentDownloadURL `
    -AutoReplace:($Env:AA_AutoReplace -eq [bool]::TrueString) `
    -ModuleList @( `
            @{ `
                ModuleName      = 'Az.Accounts'; `
                ModuleVersion   = [version]$Env:AA_Az_Accounts_MinimumVersion; `
                MaximumVersion  = [version]$Env:AA_Az_Accounts_MaximumVersion;`
                PackageProvider = @{ `
                    Name           = 'NuGet'; `
                    Version        = [version]$Env:AA_NuGet_MinimumVersion; `
                    MaximumVersion = [version]$Env:AA_NuGet_MaximumVersion `
                } `
            } `
        ) `
    -Stages Build, Cleanup `
*>&1"

# Set the entry point to run the PowerShell script when the container starts
# and pass the environment variables as arguments to the script.
# hadolint The ENTRYPOINT instruction is used to set a SINGLE command that will be run when the container starts, and so we avoid escaping issues.)
# hadolint ignore=DL3025
ENTRYPOINT "`
$ErrorActionPreference = 'Stop'; `
$ProgressPreference = 'SilentlyContinue'; `
Set-ExecutionPolicy -ExecutionPolicy Bypass -Force; `
. \New-KEYTOSACMEAgentInstance.ps1; `
New-KEYTOSACMEAgentInstance `
    -Verbose:($Env:AA_Verbose -eq [bool]::TrueString) `
    -Debug:($Env:AA_Debug -eq [bool]::TrueString) `
    -TenantId $Env:AA_TenantId `
    -CAFriendlyName $Env:AA_CAFriendlyName `
    -CertificateSubjectName $Env:AA_CertificateSubjectName `
    -AuthenticationType $Env:AA_AuthenticationType `
    -FriendlyName $Env:AA_FriendlyName `
    -AutomaticHealthChecks:($Env:AA_AutomaticHealthChecks -eq [bool]::TrueString) `
    -URL $Env:AA_URL `
    -WebDeployDownloadURL $Env:AA_WebDeployDownloadURL `
    -ASPNetCoreRuntimeDownloadURL $Env:AA_ASPNetCoreRuntimeDownloadURL `
    -ServiceMonitorDownloadURL $Env:AA_ServiceMonitorDownloadURL `
    -AppInsightsEndpoint $Env:AA_AppInsightsEndpoint `
    -ACMEAgentDownloadURL $Env:AA_ACMEAgentDownloadURL `
    -AutoReplace:($Env:AA_AutoReplace -eq [bool]::TrueString) `
    -ModuleList @( `
            @{ `
                ModuleName      = 'Az.Accounts'; `
                ModuleVersion   = [version]$Env:AA_Az_Accounts_MinimumVersion; `
                MaximumVersion  = [version]$Env:AA_Az_Accounts_MaximumVersion; `
                PackageProvider = @{ `
                    Name            = 'NuGet'; `
                    Version         = [version]$Env:AA_NuGet_MinimumVersion; `
                    MaximumVersion  = [version]$Env:AA_NuGet_MaximumVersion `
                } `
            } `
        ) `
    -Stages ($Env:AA_Stages.Trim() -split '\s*,\s*') `
*>&1"

# Perform a health check to ensure the container is running correctly
# when the ServiceMonitor process is running. The health check will run every 30 seconds
HEALTHCHECK --start-period=60s --interval=30s --timeout=3s `
    CMD C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command "` 
if (Get-Process -Name 'ServiceMonitor' -ErrorAction SilentlyContinue) { `
    try { `
        Invoke-WebRequest   -Uri 'https://$Env:AA_CertificateSubjectName/api/Health/Overall' `
                            -ContentType 'application/json' `
                            -Headers @{ Host = $CertificateSubjectName } `
                            -UseBasicParsing `
                            -ErrorAction Stop; `
        Write-Host \"Health check passed on https://$Env:AA_CertificateSubjectName/api/Health/Overall\"; `
        exit 0; `
    } catch { `
        Write-Host \"ServiceMonitor is running but health check failed: $_\"; `
        exit 1; `
    } `
} else { `
    Write-Host 'ServiceMonitor not running (yet), skipping health check'; `
    exit 0; `
} `
"