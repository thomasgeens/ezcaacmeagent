<#
.SYNOPSIS
    Creates a new KEYTOS ACME Agent instance.
 
.DESCRIPTION
    This script provisions a new KEYTOS ACME Agent instance by performing various tasks such as authentication, downloading and installing necessary components, creating a certificate signing request, and configuring IIS.
 
.PARAMETER TenantId
    The tenant ID of the Azure AD tenant. Can be in the form of `tenant.onmicrosoft.com` or the GUID.

.PARAMETER CAFriendlyName
    The friendly name of the Issuing Intermediate SSL CA to be selected from the Issuing CA list. If omitted, the first CA in the list will be selected.
 
.PARAMETER CertificateSubjectName
    The subject name for the authentication certificate that will be used to authenticate with EZCA.
 
.PARAMETER AuthenticationType
    The authentication type to be used. Can be one of the following `Identity`, `UseDeviceCode` or `Interactive`. Default is `Identity`.
 
.PARAMETER FriendlyName
    The friendly name of the ACME agent instance. If omitted, it will be set to the Certificate Subject Name.
 
.PARAMETER AutomaticHealthChecks
    Switch to activate the EZCA managed health checks of the ACME Agent instance. Default is $false.
 
.PARAMETER URL
    The URL of the ACME Agent instance. If omitted, it will be set to `https://{CertificateSubjectName}`.
 
.PARAMETER WebDeployDownloadURL
    The URL to download the WebDeploy MSI installer. Default is `https://download.microsoft.com/download/b/d/8/bd882ec4-12e0-481a-9b32-0fae8e3c0b78/webdeploy_amd64_en-US.msi`.
 
.PARAMETER ASPNetCoreRuntimeDownloadURL
    The URL to download the ASP.NET Core Runtime installer. Default is `https://aka.ms/dotnet/9.0/daily/dotnet-hosting-win.exe`. Updated links can be found at `https://github.com/dotnet/aspnetcore`.

.PARAMETER ServiceMonitorDownloadURL
    The URL to download the Service Monitor executable. Default is `https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.10/ServiceMonitor.exe`. Updated links can be found at `https://github.com/microsoft/IIS.ServiceMonitor`.
 
.PARAMETER AppInsightsEndpoint
    The endpoint of the Application Insights instance.
 
.PARAMETER ACMEAgentDownloadURL
    The URL to download the ACME Agent ZIP file. Default is `https://download.keytos.io/Downloads/EZCAACME/ACMEAgent.zip`.
  
.PARAMETER AutoReplace
    Switch to enable or disable the automatic replacement of an existing ACME Agent instance. Default is $false.

.PARAMETER ModuleList
    List of modules to be installed. Default is `Az.Accounts` module with version `5.1.0` and maximum version `5.9.99999`. Using the NuGet package provider with version `2.8.5.208` and maximum version `2.8.5.999`.
    @(
        @{
            ModuleName      = 'Az.Accounts'
            ModuleVersion   = [version] '5.1.0'
            MaximumVersion  = [version] '5.9.99999'
            PackageProvider = @{
                Name           = 'NuGet'
                Version        = [version] '2.8.5.208'
                MaximumVersion = [version] '2.8.5.999'
            }
        }
    )
 
.PARAMETER Stages
    Stages to run: `Build`, `Deploy`, `Cleanup`, `HealthCheck`, `ServiceMonitor`. Default is all stages `Build, Deploy, Cleanup, HealthCheck, ServiceMonitor`.
    Build - Installs the required PowerShell package providers and modules, IIS role, Web Deploy MSI package, and ASP.NET Core Runtime and the ACME Agent files.
    Deploy - Authenticates to AzureAD SDK and KEYTOS EZCA, (re-)registers the ACME Agent instance, and verifies and renews the agent's certificate.
    Cleanup - Cleans up the temporary files and directories.
    HealthCheck - Verifies the health of the ACME Agent instance and the certificate.

.EXAMPLE
    New-KEYTOSACMEAgentInstance -TenantId 'tenant.onmicrosoft.com' -CertificateSubjectName 'example.com' -FriendlyName 'Example' -AuthenticationType 'Interactive' -Cleanup -AutoReplace
#>
 
function New-KEYTOSACMEAgentInstance {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = 'The tenant ID of the Azure AD tenant. Can be in the form of `tenant.onmicrosoft.com` or the GUID.')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z0-9-]+(\-[a-zA-Z0-9-]+)+$')]
        [ValidateLength(1, 64)]
        [string]$TenantId,

        [Parameter(Mandatory = $false, Position = 1, HelpMessage = 'The friendly name of the Issuing Intermediate SSL CA to be selected from the Issuing CA list. If omitted, the first CA in the list will be selected.')]
        [string]$CAFriendlyName,
 
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = 'The subject name for the authentication certificate that will be used to authenticate with EZCA.')]
        [string]$CertificateSubjectName,
 
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = 'The authentication type to be used. Default is `Identity`.')]
        [ValidateSet('Identity', 'UseDeviceCode', 'Interactive')]
        [string]$AuthenticationType = 'Identity',
 
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = 'The friendly name of the ACME agent instance, in case omitted will be set to the Certificate Subject Name.')]
        [string]$FriendlyName = $CertificateSubjectName,
 
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = 'Switch to activate the EZCA managed health checks of the ACME Agent instance. Default is $false.')]
        [switch]$AutomaticHealthChecks,
 
        [Parameter(Mandatory = $false, Position = 6, HelpMessage = 'The URL of the ACME Agent instance, in case omitted will be set to `https://{CertificateSubjectName}`.')]
        [string]$URL = "https://$CertificateSubjectName",
 
        [Parameter(Mandatory = $false, Position = 7, HelpMessage = 'The URL to download the WebDeploy MSI installer. Default is `https://download.microsoft.com/download/b/d/8/bd882ec4-12e0-481a-9b32-0fae8e3c0b78/webdeploy_amd64_en-US.msi`.')]
        [string]$WebDeployDownloadURL = 'https://download.microsoft.com/download/b/d/8/bd882ec4-12e0-481a-9b32-0fae8e3c0b78/webdeploy_amd64_en-US.msi',
 
        [Parameter(Mandatory = $false, Position = 8, HelpMessage = 'The URL to download the ASP.NET Core Runtime installer. Default is `https://aka.ms/dotnet/9.0/daily/dotnet-hosting-win.exe`. Updated links can be found at `https://github.com/dotnet/aspnetcore`.')]
        [string]$ASPNetCoreRuntimeDownloadURL = 'https://aka.ms/dotnet/9.0/daily/dotnet-hosting-win.exe',
 
        [Parameter(Mandatory = $false, Position = 9, HelpMessage = 'The URL to download the Service Monitor executable. Default is `https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.10/ServiceMonitor.exe`.')]
        [string]$ServiceMonitorDownloadURL = 'https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.10/ServiceMonitor.exe',
 
        [Parameter(Mandatory = $false, Position = 10, HelpMessage = 'The endpoint of the Application Insights instance.')]
        [string]$AppInsightsEndpoint,
 
        [Parameter(Mandatory = $false, Position = 11, HelpMessage = 'The URL to download the ACME Agent ZIP file. Default is `https://download.keytos.io/Downloads/EZCAACME/ACMEAgent.zip`.')]
        [string]$ACMEAgentDownloadURL = 'https://download.keytos.io/Downloads/EZCAACME/ACMEAgent.zip',
 
        [Parameter(Mandatory = $false, Position = 12, HelpMessage = 'Switch to enable or disable the automatic replacement of an existing ACME Agent instance. Default is $false.')]
        [switch]$AutoReplace,

        [Parameter(Mandatory = $false, Position = 19, HelpMessage = 'Module list to be used with correlating package providers. Default is `@( @{ ModuleName = ''Az.Accounts'', ModuleVersion = [version] ''5.1.0'', MaximumVersion  = [version] ''5.9.99999'', PackageProvider = @{ Name = ''NuGet'', Version = [version] ''2.8.5.208'', MaximumVersion = [version] ''2.8.5.999'' } } )`.')]
        [ValidateNotNullOrEmpty()]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'ModuleList')]
        [Object[]]$ModuleList = @(
            @{
                ModuleName      = 'Az.Accounts'
                ModuleVersion   = [version] '5.2.0'
                MaximumVersion  = [version] '5.9.99999'
                PackageProvider = @{
                    Name           = 'NuGet'
                    Version        = [version] '2.8.5.208'
                    MaximumVersion = [version] '2.8.5.999'
                }
            }
        ),

        [Parameter(Mandatory = $false, Position = 14, HelpMessage = 'Stages to run: `Build`, `Deploy`, `Cleanup`, `HealthCheck`, `ServiceMonitor`. Default is all stages `Build, Deploy, Cleanup, HealthCheck, ServiceMonitor)`.')]
        [ValidateSet('Build', 'Deploy', 'Cleanup', 'HealthCheck', 'ServiceMonitor')]
        [string[]]$Stages = @('Build', 'Deploy', 'Cleanup', 'HealthCheck', 'ServiceMonitor')

    )

    BEGIN {
        $ExecutionStartTime = Get-Date
        Write-Verbose "Beginning $($MyInvocation.Mycommand) at $ExecutionStartTime"
    }
 
    PROCESS {
        Write-Verbose "Processing $($MyInvocation.Mycommand)"
 
        #region Variables
        $TemporaryDirectoryPath = "$Env:SystemDrive\Temp"
        $WebDeployMSIPath = "$TemporaryDirectoryPath\WebDeploy.msi"
        $WebDeployLogFile = "$TemporaryDirectoryPath\WebDeployInstallation.log"
        $ASPNetCoreRuntimePath = "$TemporaryDirectoryPath\ASPNetCoreRuntime.exe"
        $CertReqExecutablePath = "$Env:SystemDrive\Windows\System32\certreq.exe"
        $CertReqInputPath = "$TemporaryDirectoryPath\certreq.inf"
        $CertReqMachineKeySet = 'TRUE'
        $CertReqCSRPath = "$TemporaryDirectoryPath\$CertificateSubjectName.csr"
        $CertUtilExecutablePath = "$Env:SystemDrive\Windows\System32\certutil.exe"
        $CertificatePKCS12BundlePath = "$TemporaryDirectoryPath\$CertificateSubjectName.pem"
        $IssuingCACertificatePath = "$TemporaryDirectoryPath\$CertificateSubjectName-issuing-ca.crt"
        $RootCACertificatePath = "$TemporaryDirectoryPath\$CertificateSubjectName-root-ca.crt"
        $IISAppPoolName = 'ezcaACMEPool'
        $IISAppName = 'ezcaACME'
        $IISrootDirectoryPath = "$Env:SystemDrive\inetpub\ezcaacmeroot"
        $ACMEAgentDownloadPath = "$TemporaryDirectoryPath\ACMEAgent.zip"
        $ServiceMonitorExecutablePath = "$Env:SystemDrive\SystemMonitor.exe"
        #endregion

        function New-FileDownload {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Url,
                [Parameter(Mandatory = $true)]
                [string]$DestinationPath
            )
            try {
                $currentProgressPreference = $ProgressPreference # Store current progress preference
                $ProgressPreference = 'SilentlyContinue' # Suppress progress bar for improved performance
                Write-Verbose "Downloading file from $Url to $DestinationPath"
                Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
                Write-Verbose "Successfully downloaded file to $DestinationPath"
            } catch {
                throw [System.Exception] "Failed to download file from $($Url): $($_.Exception.Message)"
            } finally {
                $ProgressPreference = $currentProgressPreference # Restore progress preference
            }
        }
 
        try {
            
            #region Docker Build Stage
            if ($Stages -contains 'Build') {
                if ($PSCmdlet.ShouldProcess('Docker Build Stage', 'Install')) {
                    Write-Verbose "### Docker Build Stage ####"
                    
                    # Make sure the temporary directory exists
                    Write-Verbose "Verifying the temporary directory exists at $TemporaryDirectoryPath"
                    if (-not (Test-Path $TemporaryDirectoryPath -PathType Container)) {
                        Write-Verbose "Creating the temporary directory"
                        New-Item -Path $TemporaryDirectoryPath -ItemType Directory -Force
                    }
        
                    if ($PSCmdlet.ShouldProcess('Required modules', 'Install')) {
                        Write-Verbose "Installing the required modules for $($MyInvocation.Mycommand)"
                        # [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'ModuleList')]
                        # $ModuleList = @(
                        #     @{
                        #         ModuleName      = 'Az.Accounts'
                        #         ModuleVersion   = [version] '5.1.0'
                        #         MaximumVersion  = [version] '5.9.99999'
                        #         PackageProvider = @{
                        #             Name           = 'NuGet'
                        #             Version        = [version] '2.8.5.208'
                        #             MaximumVersion = [version] '2.8.5.999'
                        #         }
                        #     }
                        # )
        
                        foreach ($Module in $ModuleList) {
                            Write-Verbose "Checking if module $($Module.ModuleName) is installed"
                            $InstalledModuleVersions = @(
                                Get-Module -ListAvailable -Name $($Module.ModuleName) -ErrorAction SilentlyContinue
                                Get-Module -Name $($Module.ModuleName) -ErrorAction SilentlyContinue
                            )
                            $FoundAcceptableVersion = $false
        
                            foreach ($ModuleVersion in $InstalledModuleVersions) {
                                if (($ModuleVersion.Version -ge $Module.ModuleVersion) -and ($ModuleVersion.Version -le $Module.MaximumVersion)) {
                                    Write-Verbose "Found acceptable version $($ModuleVersion.Version) of module $($Module.ModuleName)"
                                    $FoundAcceptableVersion = $true
                                    # Verify if the module version is already imported
                                    $ImportedModules = Get-Module -All
                                    if ($ModuleVersion.Name -notin ($ImportedModules.Name)) {
                                        Import-Module $Module.ModuleName -MinimumVersion $Module.ModuleVersion -MaximumVersion $Module.MaximumVersion -ErrorAction 'Stop'
                                        Write-Verbose "Module $($Module.ModuleName) version $($ModuleVersion.Version) is imported"
                                        break;
                                    } else {
                                        Write-Verbose "Module $($Module.ModuleName) version $($ModuleVersion.Version) is already imported"
                                        break;
                                    }
                                }
                            }
        
                            if (-not $FoundAcceptableVersion) {
                                if ($Module.PackageProvider) {
                                    Write-Verbose "Checking if package provider $($Module.PackageProvider.Name) is installed"
                                    $InstalledPackageProviderVersion = Get-PackageProvider -ListAvailable -Name $Module.PackageProvider.Name -ErrorAction SilentlyContinue
                                    if ($InstalledPackageProviderVersion.Count -eq 0) {
                                        Write-Verbose "Package provider $($Module.PackageProvider.Name) version $($Module.PackageProvider.Version) is not installed"
                                        Write-Verbose "Installing package provider $($Module.PackageProvider.Name) version $($Module.PackageProvider.Version)"
                                        Install-PackageProvider -Name "$($Module.PackageProvider.Name)" -MinimumVersion $Module.PackageProvider.Version -MaximumVersion $Module.PackageProvider.MaximumVersion -Force -ErrorAction 'Stop'
                                    } else {
                                        foreach ($PackageProviderVersion in $InstalledPackageProviderVersion) {
                                            if (($PackageProviderVersion.Version -ge $Module.PackageProvider.Version) -and ($PackageProviderVersion.Version -le $Module.PackageProvider.MaximumVersion)) {
                                                Write-Verbose "Found acceptable version $($PackageProviderVersion.Version) of package provider $($Module.PackageProvider.Name)"
                                                break;
                                            }
                                        }
                                    }
                                    if ( `
                                        ((Get-PSRepository -Name PSGallery).InstallationPolicy -eq 'Untrusted') `
                                    ) {
                                        Write-Verbose "Setting the PSGallery repository to Trusted"
                                        Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted -ErrorAction 'Stop'
                                    }
                                    Write-Verbose "Importing the package provider $($Module.PackageProvider.Name)"
                                    Import-PackageProvider -Name "$($Module.PackageProvider.Name)" -MinimumVersion $Module.PackageProvider.Version -MaximumVersion $Module.PackageProvider.MaximumVersion -ErrorAction 'Stop'
                                }
                                try {
                                    Write-Verbose "Installing the latest acceptable version of $($Module.ModuleName)"
                                    Install-Module $Module.ModuleName -MinimumVersion $Module.ModuleVersion -MaximumVersion $Module.MaximumVersion -ErrorAction 'Stop'
                                    Import-Module $Module.ModuleName -MinimumVersion $Module.ModuleVersion -MaximumVersion $Module.MaximumVersion -ErrorAction 'Stop'
                                }
                                catch {
                                    throw [System.IO.FileNotFoundException] "No acceptable installed version found for module: $($Module.ModuleName)
                                    Required Min Version: $($Module.ModuleVersion) | Max Version: $($Module.MaximumVersion)
                                    Run Get-InstalledModule to see a list of currently installed modules
                                    Run SetUp.ps1 or Install-Module $($Module.ModuleName) -Force -MaximumVersion $($Module.MaximumVersion) to install the latest acceptable version of $($Module.ModuleName)
                                    $_.Exception.Message"
                                }
                            }
                        }
                    }

                    # Install the IIS role
                    Write-Verbose "Verify if the IIS role is installed"
                    if ((Get-WindowsFeature -Name Web-Server -Debug:$false).InstallState -ne 'Installed') {
                        Write-Verbose "The IIS role will be installed"
                        Install-WindowsFeature -name Web-Server -IncludeManagementTools
                        Write-Verbose "Successfully installed the IIS role"
                    } else {
                        Write-Verbose "The IIS role was already installed, we'll assume the Web Deploy role is also installed and we'll skip its installation!"
                        $SkipWebDeployInstallation = $true
                    }
        
                    # Verify if the "Default Web Site" exists and if so remove it
                    Write-Verbose "Verifying if the IIS site 'Default Web Site' still exists"
                    $DefaultWebSite = Get-Website -Name 'Default Web Site' -ErrorAction SilentlyContinue
                    if ($DefaultWebSite) {
                        Write-Verbose "The IIS site 'Default Web Site' exists and will be removed"
                        Remove-IISSite -Name 'Default Web Site' -Confirm:$false -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        Write-Verbose "Successfully removed the IIS site 'Default Web Site'"
                    } else {
                        Write-Verbose "The 'Default Web Site' does not exist, existing IIS sites:"
                        Write-Verbose "$(Get-IISSite | Format-Table | Out-String)"
                    }
        
                    # Download the Web Deploy MSI package
                    if (-not $SkipWebDeployInstallation) {
                        # See IIS role installation above
                        if ($PSCmdlet.ShouldProcess('Web Deploy MSI package', 'Install')) {
                            Write-Verbose "Verifing if the Web Deploy MSI package has already been installed"
                            $WebDeployInstalled = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like 'Microsoft Web Deploy*' }
                            if ($WebDeployInstalled) {
                                Write-Verbose "The Web Deploy MSI package has already been installed"
                                Write-Verbose "$($WebDeployInstalled | Format-Table | Out-String)"
                            } else {
                                Write-Verbose "Downloading the Web Deploy MSI package"
                                New-FileDownload -Url $WebDeployDownloadURL -DestinationPath $WebDeployMSIPath
                                Write-Verbose "Successfully downloaded the Web Deploy MSI package"
                                Write-Verbose (Get-Item -Path $WebDeployMSIPath | Format-Table | Out-String)

                                # Install the Web Deploy MSI package silently
                                Write-Verbose "Installing the Web Deploy MSI package silently"
                                $InstallWebDeployMSI = Start-Process 'msiexec.exe' -ArgumentList "/i ""$WebDeployMSIPath"" /l*v ""$WebDeployLogFile"" /qn" -Wait -PassThru -ErrorAction Continue
                                if ($InstallWebDeployMSI.ExitCode -eq 0) {
                                    Write-Verbose "Successfully installed the Web Deploy MSI package"
                                    Write-Verbose (Get-Content -Path $WebDeployLogFile | Out-String)
                                } else {
                                    throw [System.Exception] "Failed to install the Web Deploy MSI package: $($InstallWebDeployMSI.ExitCode) - See $WebDeployLogFile for more details"
                                }
                            }
                        }
                    }

                    # Verify if the ASP.NET Core Runtime is installed
                    if ($PSCmdlet.ShouldProcess('ASP.NET Core Runtime', 'Install')) {
                        Write-Verbose "Verifying if the ASP.NET Core Runtime has already been installed"
                        $ASPNetCoreRuntimeInstalled = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like 'Microsoft ASP.NET Core*' }
                        if ($ASPNetCoreRuntimeInstalled) {
                            Write-Verbose "The ASP.NET Core Runtime has already been installed"
                            Write-Verbose "$($ASPNetCoreRuntimeInstalled | Format-Table | Out-String)"
                        } else {
                            # Download the ASP.NET Core Runtime
                            Write-Verbose "Downloading the ASP.NET Core Runtime"
                            New-FileDownload -Url $ASPNetCoreRuntimeDownloadURL -DestinationPath $ASPNetCoreRuntimePath
                            Write-Verbose "Successfully downloaded the ASP.NET Core Runtime"
                            Write-Verbose (Get-Item -Path $ASPNetCoreRuntimePath | Format-Table | Out-String)

                            # Install the ASP.NET Core Runtime silently
                            Write-Verbose "Installing the ASP.NET Core Runtime silently"
                            Start-Process $ASPNetCoreRuntimePath -ArgumentList "/quiet" -Wait
                            Write-Verbose "Successfully installed the ASP.NET Core Runtime"
                        }
                    }

                    # Creating the IISWebrootDirectoryPath
                    Write-Verbose "Creating the IIS Webroot directory path ($IISrootDirectoryPath)"
                    if ((Test-Path $IISrootDirectoryPath -pathType container) -eq $false) {
                        New-Item -Path $IISrootDirectoryPath -ItemType Directory -Force
                    }
                    Write-Verbose "Created the IIS Webroot directory path"
                    Write-Verbose (Get-Item -Path $IISrootDirectoryPath | Format-Table | Out-String)

                    # Download the ACME Agent
                    Write-Verbose "Verifying if the ACME Agent's installation file hosted online is already downloaded"
                    $ACMEAgentDownloadedFile = Test-Path $ACMEAgentDownloadPath -PathType Leaf
                    $ACMEAgentDownloadedFileEqualSize = $false
                    if ($ACMEAgentDownloadedFile) {
                        $ACMEAgentDownloadedFile = Get-Item -Path $ACMEAgentDownloadPath
                        $ACMEAgentDownloadedFileSize = $ACMEAgentDownloadedFile.Length
                        $ACMEAgentDownloadedFileLastWriteTime = $ACMEAgentDownloadedFile.LastWriteTime
                        $ACMEAgentDownloadedFileLastWriteTime = $ACMEAgentDownloadedFileLastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                        $iwrACMEAgentDownloadURL = Invoke-WebRequest -Uri $ACMEAgentDownloadURL -Method Head -UseBasicParsing
                        $ACMEAgentDownloadURLFileSize = $iwrACMEAgentDownloadURL.Headers['Content-Length']
                        $ACMEAgentDownloadURLLastModified = $iwrACMEAgentDownloadURL.Headers['Last-Modified']
                        $ACMEAgentDownloadURLLastModified = [DateTime]::ParseExact($ACMEAgentDownloadURLLastModified, 'ddd, dd MMM yyyy HH:mm:ss GMT', [System.Globalization.CultureInfo]::InvariantCulture)
                        $ACMEAgentDownloadURLLastModified = $ACMEAgentDownloadURLLastModified.ToString('yyyy-MM-dd HH:mm:ss')
                        $ACMEAgentDownloadedFileEqualSize = $ACMEAgentDownloadedFileSize -eq $ACMEAgentDownloadURLFileSize
                        if ($ACMEAgentDownloadedFileEqualSize) {
                            Write-Verbose "The ACME Agent's installation file locally is equal in the size to the file hosted online"
                            Write-Verbose "ACME Agent's installation file locally: $($ACMEAgentDownloadedFile.FullName) - $($ACMEAgentDownloadedFileSize) bytes - $($ACMEAgentDownloadedFileLastWriteTime)"
                            Write-Verbose "ACME Agent's installation file hosted online: $($ACMEAgentDownloadURL) - $($ACMEAgentDownloadURLFileSize) bytes - $($ACMEAgentDownloadURLLastModified)"
                        }
                    }
                    if ($ACMEAgentDownloadedFile -eq $false -or $ACMEAgentDownloadedFileEqualSize -eq $false) {
                        Write-Verbose "Downloading the ACME Agent's installation file"
                        New-FileDownload -Url $ACMEAgentDownloadURL -DestinationPath $ACMEAgentDownloadPath
                        Write-Verbose "Successfully downloaded the ACME Agent's installation file"
                        Write-Verbose (Get-Item -Path $ACMEAgentDownloadPath | Format-Table | Out-String)
                        Write-Verbose "Cleaning up the current ACME Agent's installation ($IISrootDirectoryPath)"
                        Remove-Item -Path "$IISrootDirectoryPath\*" -Recurse -Force -ErrorAction SilentlyContinue
                    } else {
                        Write-Verbose "The ACME Agent's installation file hosted was already downloaded"
                    }
        
                    # Extract the ACME Agent
                    Write-Verbose "Extracting the ACME Agent"
                    Expand-Archive -LiteralPath $ACMEAgentDownloadPath -DestinationPath $IISrootDirectoryPath -Force -ErrorAction SilentlyContinue
                    Write-Verbose "Successfully extracted the ACME Agent"
                    Write-Verbose (Get-ChildItem -Path $IISrootDirectoryPath | Format-Table | Out-String)

                    # Take a copy of the appsettings.json file to set as a default backup
                    Write-Verbose "Taking a copy of the appsettings.json file to set as a default backup"
                    $AppSettingsFile = "$IISrootDirectoryPath\appsettings.json"
                    $AppSettingsFileBackup = "$IISrootDirectoryPath\appsettings.json.default"
                    if (Test-Path -Path $AppSettingsFileBackup -PathType Leaf) {
                        Remove-Item -Path $AppSettingsFileBackup -Force
                    }
                    Copy-Item -Path $AppSettingsFile -Destination $AppSettingsFileBackup -Force
                    Write-Verbose "Successfully took a copy of the appsettings.json file to set as a default backup"
                    Write-Verbose (Get-Item -Path $AppSettingsFileBackup | Format-Table | Out-String)

                    Write-Verbose "Downloading the Service Monitor's executable file ($ServiceMonitorExecutablePath)"
                    if (Test-Path -Path $ServiceMonitorExecutablePath -PathType Leaf) {
                        Write-Verbose "The Service Monitor's executable is already downloaded"
                        Write-Verbose (Get-Item -Path $ServiceMonitorExecutablePath | Format-Table | Out-String)
                    } else {
                        New-FileDownload -Url $ServiceMonitorDownloadURL -DestinationPath $ServiceMonitorExecutablePath
                        Write-Verbose "Successfully downloaded the Service Monitor executable to $ServiceMonitorExecutablePath"
                    }                   
                }
            }
            #endregion
 
            #region ACME Agent Instance Setup Stage
            if ($Stages -contains 'Deploy') {
                if ($PSCmdlet.ShouldProcess('ACME Agent Instance', 'Install')) {
                    Write-Verbose "### ACME Agent Instance Deploy Stage ####"

                    #region Authentication
                    if ($PSCmdlet.ShouldProcess('AzureAD SDK', 'Connect')) {
                        Write-Verbose "Authenticating to AzureAD SDK with Tenant ID: $($tenantId)"

                        $LoginExperienceV2 = Get-AzConfig -LoginExperienceV2

                        try {
                            # Avoid having to select a subscription
                            Set-AzConfig -LoginExperienceV2:Off -Confirm:$false

                            switch ($AuthenticationType) {
                                'UseDeviceCode' {
                                    Write-Verbose "Using Device Code Authentication"
                                    Connect-AzAccount -Environment AzureCloud -Tenant $tenantId -UseDeviceAuthentication
                                } 'Interactive' {
                                    Write-Verbose "Using Interactive Authentication"
                                    Connect-AzAccount -Environment AzureCloud -Tenant $tenantId -InformationAction Ignore
                                } default {
                                    Write-Verbose "Using Identity Authentication"
                                    Connect-AzAccount -Environment AzureCloud -Tenant $tenantId -Identity
                                }
                            }
                        }
                        finally {
                            # Restore the original login experience
                            Set-AzConfig -LoginExperienceV2:$LoginExperienceV2.Value -Confirm:$false
                        }
                    }

                    $CurrentContext = Get-AzContext
                    $CurrentSubscription = Get-AzSubscription -SubscriptionId $CurrentContext.Subscription.Id
                    Write-Verbose "Successfully authenticated against AzureAD SDK as $($CurrentContext.Account.Id) ($($CurrentSubscription.Name))"

                    Write-Verbose "Requesting a new AzureAD access token to be used as a bearer token (API key) for the KEYTOS EZCA API"
                    $bearerToken = ConvertTo-SecureString -AsPlainText (Get-AzAccessToken -TenantId $TenantId -ErrorAction Stop).Token -Force
                    Write-Verbose "Successfully retrieved a new AzureAD access token"
                    Write-Verbose $bearerToken
                    #endregion

                    #region Register ACME Agent Instance
                    Write-Verbose "Verifying the temporary directory exists at $TemporaryDirectoryPath"
                    if (-not (Test-Path $TemporaryDirectoryPath -PathType Container)) {
                        Write-Verbose "Creating the temporary directory"
                        New-Item -Path $TemporaryDirectoryPath -ItemType Directory -Force
                    }

                    Write-Verbose "Retrieving the list of CAs"
                    $MyCAs = @()
                    $iwrMyCAs = Invoke-WebRequest   -Method GET `
                        -Uri 'https://eu.ezca.io/api/CA/GetMyCAs' `
                        -ContentType 'application/json' `
                        -Headers @{
                        Authorization = "Bearer $([System.Net.NetworkCredential]::new('', $bearerToken).Password)"
                    } `
                        -UseBasicParsing
                    if ($iwrMyCAs.StatusCode -eq 200 -and (ConvertFrom-Json $iwrMyCAs.Content).Success -eq $true) {
                        $MyCAs = ConvertFrom-Json (ConvertFrom-Json $iwrMyCAs.Content).Message
                        Write-Verbose "Successfully retrieved the list of CAs:"
                        Write-Verbose "$($MyCAs | Format-Table | Out-String)"
                        if ($MyCAs.Count -eq 0) {
                            throw [System.Exception] "No CAs found"
                        }
                    } else {
                        throw [System.Exception] "Failed to retrieve the list of CAs"
                    }

                    # Get Issuing Intermediate CAs
                    $IssuingIntermediateCAs = $MyCAs | Where-Object { $_.CAType -eq 'PrivateCA' -and $_.CATier -eq 'SubordinateCA' }
                    Write-Verbose "Successfully retrieved the list of Issuing Intermediate CAs:"
                    Write-Verbose "$($IssuingIntermediateCAs | Format-Table | Out-String)"
                    if ($IssuingIntermediateCAs.Count -eq 0) {
                        throw [System.Exception] "No Issuing Intermediate CAs found"
                    }

                    # Get Selected Issuing Intermediate SSL CA if the CAFriendlyName is provided, else the first one will be selected
                    if ($null -eq $CAFriendlyName) {
                        Write-Verbose "No CAFriendlyName provided, selecting the first Issuing Intermediate SSL CA"
                        $SelectedIssuingIntermediateSSLCA = $IssuingIntermediateCAs | Select-Object -First 1
                    } else {
                        Write-Verbose "Getting the Selected Issuing Intermediate SSL CA with CAFriendlyName: $($CAFriendlyName)"
                        $SelectedIssuingIntermediateSSLCA = $IssuingIntermediateCAs | Where-Object { $_.CAFriendlyName -eq $CAFriendlyName }
                    }
                    if ($SelectedIssuingIntermediateSSLCA.Count -eq 0) {
                        throw [System.Exception] "No Selected Issuing Intermediate SSL CA found"
                    } else {
                        Write-Verbose "Successfully retrieved the Selected Issuing Intermediate SSL CA:"
                        Write-Verbose "$($SelectedIssuingIntermediateSSLCA | Format-Table | Out-String)"
                    }

                    # Get latest active Selected Issuing Intermediate SSL CA via
                    # Status = Active and ExpiryDate = Max(ExpiryDate)
                    $LatestActiveSelectedIssuingIntermediateSSLCA = $SelectedIssuingIntermediateSSLCA.LocalCAs | Sort-Object -Property ExpiryDate -Descending | Select-Object -First 1
                    if ($null -eq $LatestActiveSelectedIssuingIntermediateSSLCA) {
                        throw [System.Exception] "No latest active Selected Issuing Intermediate SSL CA found"
                    } else {
                        Write-Verbose "Successfully retrieved the latest active Selected Issuing Intermediate SSL CA:"
                        Write-Verbose "$($LatestActiveSelectedIssuingIntermediateSSLCA | Format-Table | Out-String)"
                    }

                    # Verify there isn't an ACME Agent instance with the same Certificate Subject Name
                    Write-Verbose "Verifying there isn't an ACME Agent instance with the same Certificate Subject Name"
                    $caID = @{
                        caID = $LatestActiveSelectedIssuingIntermediateSSLCA.CAID
                    }
                    $iwrGetACMEAgentInstances = Invoke-WebRequest   -Method GET `
                        -Uri 'https://eu.ezca.io/api/CA/GetACMECADetails' `
                        -ContentType 'application/json' `
                        -Body $caID `
                        -Headers @{
                        Authorization = "Bearer $([System.Net.NetworkCredential]::new('', $bearerToken).Password)"
                    } `
                        -UseBasicParsing
                    if ($iwrGetACMEAgentInstances.StatusCode -eq 200 -and (ConvertFrom-Json $iwrGetACMEAgentInstances.Content).IsEligible -eq $true) {
                        $ACMEAgentInstances = (ConvertFrom-Json $iwrGetACMEAgentInstances.Content).Agents
                        if ($null -ne $ACMEAgentInstances) {
                            $ExistingACMEAgentInstance = $ACMEAgentInstances | Where-Object { $_.CertSubjectName -eq $CertificateSubjectName }
                            if ($ExistingACMEAgentInstance) {
                                Write-Verbose "An ACME Agent instance with the same Certificate Subject Name already exists and AutoReplace is NOT enabled:`n$($ExistingACMEAgentInstance | Format-Table | Out-String)"
                                if ($AutoReplace -and $PSCmdlet.ShouldProcess("Existing ACME Agent Instance $($ExistingACMEAgentInstance.Name)", 'Delete')) {
                                    Write-Verbose "AutoReplace is enabled, deleting the existing ACME Agent instance ($($ExistingACMEAgentInstance.Name))"
                                    $DeleteACMEAgentInstance = @{
                                        TenantID        = $ExistingACMEAgentInstance.TenantID
                                        SUBID           = $ExistingACMEAgentInstance.SUBID
                                        CAID            = $ExistingACMEAgentInstance.CAID
                                        CertSubjectName = $ExistingACMEAgentInstance.CertSubjectName
                                        Name            = $ExistingACMEAgentInstance.Name
                                        URL             = $ExistingACMEAgentInstance.URL
                                        TestHealth      = $ExistingACMEAgentInstance.TestHealth
                                    }
                                    $iwrDeleteACMEAgentInstance = Invoke-WebRequest   -Method POST `
                                        -Uri 'https://eu.ezca.io/api/CA/DeleteACMEAgent' `
                                        -ContentType 'application/json' `
                                        -Body ($DeleteACMEAgentInstance | ConvertTo-Json) `
                                        -Headers @{
                                        Authorization = "Bearer $([System.Net.NetworkCredential]::new('', $bearerToken).Password)"
                                    } `
                                        -UseBasicParsing
                                    if ($iwrDeleteACMEAgentInstance.StatusCode -eq 200 -and (ConvertFrom-Json $iwrDeleteACMEAgentInstance.Content).Success -eq $true) {
                                        $DeleteACMEAgentInstance = (ConvertFrom-Json $iwrDeleteACMEAgentInstance.Content).Message
                                        Write-Verbose "Successfully deleted the existing ACME Agent instance:"
                                        Write-Verbose "$($DeleteACMEAgentInstance | Format-Table | Out-String)"
                                    } else {
                                        throw [System.Exception] "Failed to delete the existing ACME Agent instance: $((ConvertFrom-Json $iwrDeleteACMEAgentInstance.Content).Message)"
                                    }
                                } else {
                                    throw [System.Exception] "An ACME Agent instance with the same Certificate Subject Name already exists:`n$($ExistingACMEAgentInstance | Format-Table | Out-String)"
                                }
                            }
                        }
                    } else {
                        throw [System.Exception] "Failed to verify there isn't an ACME Agent instance with the same Certificate Subject Name: $(ConvertFrom-Json $iwrGetACMEAgentInstances.Content)"
                    }

                    # Verify if the domain for the certificate subject name is already registered and approved
                    #- Get my domains
                    Write-Verbose "Getting the list of all my domains"
                    $MyDomains = @()
                    $iwrMyDomains = Invoke-WebRequest   -Method GET `
                        -Uri 'https://eu.ezca.io/api/CA/GetMyDomains' `
                        -ContentType 'application/json' `
                        -Headers @{
                        Authorization = "Bearer $([System.Net.NetworkCredential]::new('', $bearerToken).Password)"
                    } `
                        -UseBasicParsing
                    if ($iwrMyDomains.StatusCode -eq 200 -and (ConvertFrom-Json $iwrMyDomains.Content).Success -eq $true) {
                        $MyDomains = ConvertFrom-Json (ConvertFrom-Json $iwrMyDomains.Content).Message
                        Write-Verbose "Successfully retrieved the list of domains:"
                        Write-Verbose "$($MyDomains | Format-Table | Out-String)"
                    } else {
                        throw [System.Exception]  "Failed to retrieve the list of domains: $((ConvertFrom-Json $iwrMyDomains.Content).Message)"
                    }
                    #-Verify the domain for the certificate subject name was already registered and approved
                    Write-Verbose "Verifying if the domain for the certificate subject name $($CertificateSubjectName) is already registered"
                    $Domain = $MyDomains | Where-Object { $_.Domain -eq $CertificateSubjectName } | Select-Object -First 1
                    if ($null -ne $Domain) {
                        Write-Verbose "The domain for the certificate subject name $($CertificateSubjectName) is already registered"
                        Write-Verbose "$($Domain | Format-Table | Out-String)"
                        if ($AutoReplace -and ($PSCmdlet.ShouldProcess("Existing Domain $($Domain.Domain)", 'Delete'))) {
                            Write-Verbose "AutoReplace is enabled, deleting the existing domain ($($Domain.Domain))"
                            $DeleteDomain = @{
                                caID       = "$($LatestActiveSelectedIssuingIntermediateSSLCA.CAID)"
                                domain     = "$($Domain.Domain)"
                                templateID = "$($Domain.TemplateID)"
                            }
                            $iwrDeleteDomain = Invoke-WebRequest   -Method DELETE `
                                -Uri "https://eu.ezca.io/api/CA/DeleteDomain?caID=$($LatestActiveSelectedIssuingIntermediateSSLCA.CAID)&domain=$($Domain.Domain)&templateID=$($Domain.TemplateID)" `
                                -Body $DeleteDomain `
                                -Headers @{
                                Authorization = "Bearer $([System.Net.NetworkCredential]::new('', $bearerToken).Password)"
                            } `
                                -UseBasicParsing
                            if ($iwrDeleteDomain.StatusCode -eq 200 -and (ConvertFrom-Json $iwrDeleteDomain.Content).Success -eq $true) {
                                $DeleteDomain = (ConvertFrom-Json $iwrDeleteDomain.Content).Message
                                Write-Verbose "Successfully deleted the existing domain:"
                                Write-Verbose "$($DeleteDomain | Format-Table | Out-String)"
                            } else {
                                throw [System.Exception] "Failed to delete the existing domain: $((ConvertFrom-Json $iwrDeleteDomain.Content).Message)"
                            }
                        } else {
                            throw [System.Exception] "The domain for the certificate subject name $($CertificateSubjectName) is already registered and AutoReplace is NOT enabled"
                        }
                    } else {
                        Write-Verbose "The domain for the certificate subject name $($CertificateSubjectName) is still available"
                    }


                    # Register a new ACME Agent instance
                    Write-Verbose "Creating a new ACME Agent instance for $($CertificateSubjectName) with friendly name $($FriendlyName)"
                    $ACMEAgentInstance = @{
                        TenantID        = $LatestActiveSelectedIssuingIntermediateSSLCA.TenantId
                        SUBID           = $LatestActiveSelectedIssuingIntermediateSSLCA.SUBID
                        CAID            = $LatestActiveSelectedIssuingIntermediateSSLCA.CAID
                        CertSubjectName = $CertificateSubjectName
                        Name            = $FriendlyName
                        URL             = $URL
                        TestHealth      = $AutomaticHealthChecks.IsPresent
                    }
                    Write-Verbose "ACME Agent instance details which will be used:"
                    Write-Verbose "$($ACMEAgentInstance | ConvertTo-Json)"
                    $iwrRegisterACMEAgentInstance = Invoke-WebRequest   -Method POST `
                        -Uri 'https://eu.ezca.io/api/CA/RegisterACMEAgent' `
                        -ContentType 'application/json' `
                        -Body ($ACMEAgentInstance | ConvertTo-Json) `
                        -Headers @{
                        Authorization = "Bearer $([System.Net.NetworkCredential]::new('', $bearerToken).Password)"
                    } `
                        -UseBasicParsing
                    if ($iwrRegisterACMEAgentInstance.StatusCode -eq 200 -and (ConvertFrom-Json $iwrRegisterACMEAgentInstance.Content).Success -eq $true) {
                        $RegisterACMEAgentInstance = (ConvertFrom-Json $iwrRegisterACMEAgentInstance.Content).Message
                        Write-Verbose "Successfully registered the ACME Agent instance:"
                        Write-Verbose "$($RegisterACMEAgentInstance | Format-Table | Out-String)"
                    } else {
                        throw [System.Exception]  "Failed to register the ACME Agent instance: $((ConvertFrom-Json $iwrRegisterACMEAgentInstance.Content).Message)"
                    }
                
                    # Verifying if we still have a valid certificate in the local machine store for the Certificate Subject Name and it has not expired using certutil
                    Write-Verbose "Verifying if we still have a valid certificate in the local machine store for the Certificate Subject Name ($CertificateSubjectName)"
                    $CertUtilCerts = "$TemporaryDirectoryPath\certutil-certs.txt"
                    Start-Process $CertUtilExecutablePath -ArgumentList "-store My `"$CertificateSubjectName`"" -Wait -NoNewWindow -PassThru -RedirectStandardOutput $CertUtilCerts -ErrorAction Continue | Out-Null
                    $Certificates = @()
                    Get-Content -Path $CertUtilCerts | Where-Object { $_ -match 'Serial Number' -or $_ -match 'NotAfter' } | ForEach-Object {
                        if ($_ -match 'Serial Number') {
                            $Certificate = [PSCustomObject]@{
                                SerialNumber = ($_ -split ':')[1].Trim()
                            }
                        } elseif ($_ -match 'NotAfter') {
                            # Add the NotAfter property to the certificate object as a DateTime (example: 9/15/2025 10:49 AM)
                            $NotAferString = ($_ -split ': ')[1].Trim()
                            $NotAfter = [DateTime]::ParseExact($NotAferString, 'M/d/yyyy h:mm tt', $null)
                            $Expired = $NotAfter -lt (Get-Date)
                            $Certificate | Add-Member -MemberType NoteProperty -Name 'NotAfter' -Value [datetime]$NotAfter
                            $Certificate | Add-Member -MemberType NoteProperty -Name 'Expired' -Value $Expired
                            $Certificates += $Certificate
                        }
                    }
                    $ValidCertificate = $false
                    if ($Certificates.Count -ne 0) {
                        Write-Verbose "Retrieved the following certificates from the local machine store"
                        Write-Verbose "$($Certificates | Format-Table | Out-String)"
    
                        $ExpiredCertificates = @($Certificates | Where-Object { $_.Expired -eq $true })
                        if ($ExpiredCertificates.Count -gt 0) {
                            Write-Verbose "The following certificates are expired and will be deleted"
                            Write-Verbose "$($ExpiredCertificates | Format-Table | Out-String)"
                            if ($AutoReplace -and $PSCmdlet.ShouldProcess("Expired Certificates for Certificate Subject Name ($CertificateSubjectName)", 'Delete')) {
                                Write-Verbose "AutoReplace is enabled, deleting the expired certificates for the Certificate Subject Name ($CertificateSubjectName)"
                                $ExpiredCertificates | ForEach-Object {
                                    Write-Verbose "Deleting the expired certificate for the Certificate Subject Name ($($_.SerialNumber))"
                                    Start-Process $CertUtilExecutablePath -ArgumentList "-delstore My `"$($_.SerialNumber)`"" -Wait -NoNewWindow -PassThru -ErrorAction Stop | Out-Null
                                    Write-Verbose "Successfully deleted the expired certificate for the Certificate Subject Name ($CertificateSubjectName)"
                                }
                            } else {
                                throw [System.Exception] "Expired certificates are available in the local machine store for the Certificate Subject Name ($CertificateSubjectName)"
                            }
                        }
    
                        $ValidCertificates = @($Certificates | Where-Object { $_.Expired -eq $false })
                        if ($ValidCertificates.Count -gt 1) {
                            if ($AutoReplace -and $PSCmdlet.ShouldProcess("Existing Certificates for Certificate Subject Name ($CertificateSubjectName)", 'Delete')) {
                                Write-Verbose "AutoReplace is enabled, deleting the existing certificates for the Certificate Subject Name ($CertificateSubjectName)"
                                $Certificates[1..$Certificates.count] | ForEach-Object {
                                    Write-Verbose "Deleting the existing certificate for the Certificate Subject Name ($($_.SerialNumber))"
                                    Start-Process $CertUtilExecutablePath -ArgumentList "-delstore My `"$($_.SerialNumber)`"" -Wait -NoNewWindow -PassThru -ErrorAction Stop | Out-Null
                                    Write-Verbose "Successfully deleted the existing certificate for the Certificate Subject Name ($CertificateSubjectName)"
                                }
                            } else {
                                throw [System.Exception] "More than one valid certificate is available in the local machine store for the Certificate Subject Name ($CertificateSubjectName)"
                            }
                        } elseif ($ValidCertificates.Count -eq 1) {
                            Write-Verbose "A valid certificate is still available in the local machine store for the Certificate Subject Name ($CertificateSubjectName)"
                            Write-Verbose "$($ValidCertificates | Format-Table | Out-String)"
                            $ValidCertificate = $true
                        } else {
                            Write-Verbose "No valid certificate is available yet in the local machine store for the Certificate Subject Name ($CertificateSubjectName)"
                        }
                    }
    
                    if (-not $ValidCertificate) {
                        # Create a Certificate Signing Request (CSR) for the ACME agent
                        Write-Verbose "Creating a Certificate Signing Request (CSR) input file for the ACME agent ($CertificateSubjectName)"
                        #- Build SAN list
                        $SANList = @($CertificateSubjectName)
                        $Extension2_5_29_17 = "{text}dns=$($SANList -join '&dns=')"
                        #- Create CertReq input inf file
                        $CertReqInput = @"
;----------------- request.inf -----------------

[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "CN=$CertificateSubjectName"

KeySpec = 1
KeyLength = 4096
Exportable = FALSE
MachineKeySet = $CertReqMachineKeySet
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xA0
HashAlgorithm = SHA256

[Extensions]
2.5.29.17 = "$Extension2_5_29_17"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.2
OID=1.3.6.1.5.5.7.3.1

;-----------------------------------------------
"@
                        #- Save CertReq input inf file
                        Write-Verbose "Saving the CertReq input inf file ($CertReqInputPath)"
                        $CertReqInput | Out-File -FilePath $CertReqInputPath -Encoding ascii -Force
                        Write-Verbose "Successfully saved the CertReq input inf file ($CertReqInputPath)"
                        Write-Verbose (Get-Content -Path $CertReqInputPath | Out-String)
                        #- Create CSR
                        Write-Verbose "Creating a new Certificate Signing Request (CSR) in the the local machine store"
                        Start-Process $CertReqExecutablePath -ArgumentList "-q -f -new `"$CertReqInputPath`" `"$CertReqCSRPath`"" -Wait
                        Write-Verbose "Successfully created a new Certificate Signing Request (CSR) in the the local machine store"
                        Write-Verbose (Get-Content -Path $CertReqCSRPath | Out-String)
                        #- Get CSR content
                        $CertReqCSR = Get-Content -Path $CertReqCSRPath -Raw
    
                        # Get the CA Templates for the latest active Selected Issuing Intermediate SSL CA
                        Write-Verbose "Getting the CA Templates for the latest active Selected Issuing Intermediate SSL CA ($($LatestActiveSelectedIssuingIntermediateSSLCA.CAID))"
                        $caID = @{
                            caID = $LatestActiveSelectedIssuingIntermediateSSLCA.CAID
                        }
                        $iwrGetCATemplates = Invoke-WebRequest  -Method GET `
                            -Uri 'https://eu.ezca.io/api/CA/GetCATemplates' `
                            -ContentType 'application/json' `
                            -Body $caID `
                            -Headers @{
                            Authorization = "Bearer $([System.Net.NetworkCredential]::new('', $bearerToken).Password)"
                        } `
                            -UseBasicParsing
                        if ($iwrGetCATemplates.StatusCode -eq 200 -and (ConvertFrom-Json $iwrGetCATemplates.Content).Count -gt 0) {
                            $GetCATemplates = (ConvertFrom-Json $iwrGetCATemplates.Content)
                            Write-Verbose "Successfully retrieved the CA Templates for the latest active Selected Issuing Intermediate SSL CA"
                            Write-Verbose "$($GetCATemplates | Format-Table | Out-String)"
                        } else {
                            throw [System.Exception] "Failed to retrieve the CA Templates for the latest active Selected Issuing Intermediate SSL CA: $(ConvertFrom-Json $iwrGetCATemplates.Content)"
                        }
    
                        # Get the CA Template from the CA Templates of CATemplateType 'SSL Template'
                        Write-Verbose "Getting the SSL Template from the CA Templates"
                        $SSLTemplate = ($GetCATemplates | Where-Object { $_.CATemplateType -eq 'SSL Template' })
                        if ($SSLTemplate) {
                            Write-Verbose "Successfully retrieved the SSL Template from the CA Templates"
                            Write-Verbose "$($SSLTemplate | Format-Table | Out-String)"
                        } else {
                            throw [System.Exception] "Failed to retrieve the SSL Template from the CA Templates"
                        }
    
                        # Submit the CSR to the latest active Selected Issuing Intermediate SSL CA
                        Write-Verbose "Submitting the CSR for signing to the latest active Selected Issuing Intermediate SSL CA"
                        $RequestSSLCertificateV2 = @{
                            SubjectName         = "$CertificateSubjectName"
                            SubjectAltNames     = @(
                                @{
                                    ValueSTR       = "$CertificateSubjectName"
                                    SubjectAltType = 2
                                }
                            )
                            CAID                = $LatestActiveSelectedIssuingIntermediateSSLCA.CAID
                            TemplateID          = $SSLTemplate.TemplateID
                            CSR                 = "$CertReqCSR"
                            ValidityInDays      = $SSLTemplate.MaxCertLifeDays
                            EKUs                = @("1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.1")
                            KeyUsages           = @("Digital Signature", "Key Encipherment")
                            SelectedLocation    = "Import CSR"
                            ResourceID          = ""
                            SecretName          = "$CertificateSubjectName"
                            AKVName             = ""
                            AutoRenew           = $false
                            AutoRenewPercentage = 80
                            CertAppID           = ""
                            CertificateTags     = ""
                            SID                 = ""
                        }
                        $iwrRequestSSLCertificateV2 = Invoke-WebRequest -Method POST `
                            -Uri 'https://eu.ezca.io/api/CA/RequestSSLCertificateV2' `
                            -ContentType 'application/json' `
                            -Body ($RequestSSLCertificateV2 | ConvertTo-Json) `
                            -Headers @{
                            Authorization = "Bearer $([System.Net.NetworkCredential]::new('', $bearerToken).Password)"
                        } `
                            -UseBasicParsing
                        if ($iwrRequestSSLCertificateV2.StatusCode -eq 200) {
                            $SSLCertificate = @{}
                            $SSLCertificate = ConvertFrom-Json $iwrRequestSSLCertificateV2.Content
                            Write-Verbose "Successfully submitted the CSR for signing to the latest active Selected Issuing Intermediate SSL CA"
                            Write-Verbose "$($SSLCertificate | Get-Member -Name *certificate* | Format-Table | Out-String)"
                        } else {
                            throw [System.Exception] "Failed to submit the CSR to the latest active Selected Issuing Intermediate SSL CA: $(ConvertFrom-Json $iwrRequestSSLCertificateV2.Content)"
                        }
    
                        # Exporting the certificate files
                        Write-Verbose "Exporting the certificate files"
                        $SSLCertificate.CertificatePEM | ForEach-Object {
                            Out-File -InputObject $_ -FilePath $CertificatePKCS12BundlePath -Encoding ascii -Force
                            Write-Verbose "Certificate PKCS12 bundle exported to $CertificatePKCS12BundlePath"
                            Write-Verbose "$($_ | Format-Table | Out-String)"
                        }
                        $SSLCertificate.IssuingCACertificate | ForEach-Object {
                            Out-File -InputObject $_ -FilePath $IssuingCACertificatePath -Encoding ascii -Force
                            Write-Verbose "Issuing CA certificate exported to $IssuingCACertificatePath"
                            Write-Verbose "$($_ | Format-Table | Out-String)"
                        }
                        $SSLCertificate.RootCertificate | ForEach-Object {
                            Out-File -InputObject $_ -FilePath $RootCACertificatePath -Encoding ascii -Force
                            Write-Verbose "Root CA certificate exported to $RootCACertificatePath"
                            Write-Verbose "$($_ | Format-Table | Out-String)"
                        }
    
                        # Import the Root CA certificate to the Trusted Root Certification Authorities store using certutil
                        Write-Verbose "Importing the Root CA certificate to the Trusted Root Certification Authorities store"
                        Start-Process $CertUtilExecutablePath -ArgumentList "-addstore Root `"$RootCACertificatePath`"" -Wait
                        Write-Verbose "Successfully imported the Root CA certificate to the Trusted Root Certification Authorities store"
    
                        # Import the Issuing CA certificate to the Intermediate Certification Authorities store using certutil
                        Write-Verbose "Importing the Issuing CA certificate to the Intermediate Certification Authorities store"
                        Start-Process $CertUtilExecutablePath -ArgumentList "-addstore CA `"$IssuingCACertificatePath`"" -Wait
                        Write-Verbose "Successfully imported the Issuing CA certificate to the Intermediate Certification Authorities store"
    
                        # Complete the certificate request
                        Write-Verbose "Completing the certificate request and storing to the local machine store"
                        $CertReqAccept = "$TemporaryDirectoryPath\certreq-accept.txt"
                        Start-Process $CertReqExecutablePath -ArgumentList "-q -accept `"$CertificatePKCS12BundlePath`"" -Wait -NoNewWindow -PassThru -RedirectStandardOutput $CertReqAccept | Out-Null
                        $CertReqAcceptSuccess = (Get-Content -Path $CertReqAccept) -match 'Installed Certificate'
                        if ($CertReqAcceptSuccess) {
                            Write-Verbose "Successfully completed the certificate request and stored to the local machine store"
                        } else {
                            throw [System.Exception] "Failed to complete the certificate request and store to the local machine store:`n$(Get-Content -Path $CertReqAccept)"
                        }
                    }

                    # Get the Certificate Thumbprint from the local machine store using CertUtil.exe
                    Write-Verbose "Getting the Certificate Thumbprint from the local machine store"
                    $CertUtilExports = "$TemporaryDirectoryPath\certutil-exports.txt"
                    Start-Process $CertUtilExecutablePath -ArgumentList "-store My `"$CertificateSubjectName`"" -Wait -NoNewWindow -PassThru -RedirectStandardOutput $CertUtilExports | Out-Null
                    $CertificateThumbPrint = @()
                    $CertificateThumbprint = Get-Content -Path $CertUtilExports | Where-Object { $_ -match 'Cert Hash(.*?):' } | ForEach-Object { $_ -replace 'Cert Hash\(.*?\): ' } | ForEach-Object { $_.Trim() }
                    $CertificateThumbprint
                    if ($CertificateThumbprint.Count -le 0) {
                        throw [System.Exception] "Failed to retrieve the Certificate Thumbprint from the local machine store"
                    } elseif ($CertificateThumbprint.Count -gt 1) {
                        Write-Error "Multiple Certificate Thumbprints found in the local machine store"
                        Write-Error ($CertificateThumbprint | Format-Table | Out-String)
                        throw [System.Exception] "Multiple Certificate Thumbprints found in the local machine store"
                    } else {
                        Write-Verbose "Successfully retrieved the Certificate Thumbprint from the local machine store"
                        Write-Verbose ($CertificateThumbprint | Format-Table | Out-String)
                    }
    
                    #- Import the IIS Administration module
                    Write-Verbose "Importing the IIS Administration module"
                    Import-Module IISAdministration -ErrorAction Stop
                    Write-Verbose "Successfully imported the IIS Administration module"
                    Write-Verbose (Get-Module -Name IISAdministration | Format-Table | Out-String)

                    # Getting the IIS Server Manager
                    Write-Verbose "Getting the IIS Server Manager"
                    $IISManager = Get-IISServerManager
                    Write-Verbose "Successfully retrieved the IIS Server Manager"
                    Write-Verbose ($IISManager | Format-Table | Out-String)

                    #- Create the IIS App Pool
                    Write-Verbose "Verifying if the IIS App Pool ($IISAppPoolName) already exists"
                    $IISAppPool = Get-IISAppPool -Name $IISAppPoolName -ErrorAction SilentlyContinue -Debug:$false
                    if ($null -eq $IISAppPool) {
                        Write-Verbose "Creating the IIS App Pool ($IISAppPoolName)"
                        $IISAppPool = $IISManager.ApplicationPools.Add($IISAppPoolName)
                        $IISAppPool.ManagedRuntimeVersion = ''
                        Write-Verbose "Successfully created the IIS App Pool"
                        Write-Verbose ($IISAppPool | Format-Table | Out-String)
                    } else {
                        Write-Verbose "The IIS App Pool ($IISAppPoolName) already exists"
                        Write-Verbose ($IISAppPool | Format-Table | Out-String)
                    }
    
                    Start-IISCommitDelay # Delay the IIS commit to prevent the IIS service from restarting multiple times

                    # Create the IIS site and bind the certificate to it
                    Write-Verbose "Verifying if the IIS site ($IISAppName) already exists"
                    $IISSite = Get-IISSite -Name $IISAppName -ErrorAction SilentlyContinue
                    if ($null -eq $IISSite) {
                        Write-Verbose "Creating the IIS site ($IISAppName) and binding the certificate to it"
                        # Start-IISCommitDelay # Delay the IIS commit to prevent the IIS service from restarting multiple times
                        $IISSite = New-IISSite  -Name $IISAppName `
                            -PhysicalPath $IISrootDirectoryPath `
                            -BindingInformation "*:443:$CertificateSubjectName" `
                            -Protocol https `
                            -CertificateThumbPrint $CertificateThumbprint `
                            -CertStoreLocation Cert:\LocalMachine\My `
                            -SslFlag Sni `
                            -PassThru
                        # Stop-IISCommitDelay # Commit the IIS changes
                        $IISSite = Get-IISSite -Name $IISAppName -ErrorAction Stop
                        Write-Verbose "Successfully created and bound the certificate to the IIS site"
                        Write-Verbose ($IISSite | Format-Table | Out-String)
                    } else {
                        Write-Verbose "The IIS site ($IISAppName) already exists"
                        Write-Verbose ($IISSite | Format-Table | Out-String)
                        Write-Verbose "Updating the IIS Site's web binding"
                        # Start-IISCommitDelay # Delay the IIS commit to prevent the IIS service from restarting multiple times
                        $WebBinding = Get-IISSiteBinding -Name "$IISAppName" | Where-Object { $_.Protocol -eq 'https' }
                        Write-Verbose "IIS Site's web binding details (BEFORE):"
                        Write-Verbose "$($WebBinding | Format-Table Cert* | Out-String)"
                        $WebBindings = Get-IISSiteBinding -Name ezcaACME
                        for ($i = 0; $i -lt $WebBindings.Count; $i++) {
                            $WebBinding = $WebBindings[$i]
                            Remove-IISSiteBinding   -Name 'ezcaACME' `
                                -BindingInformation "*:443:$($WebBinding.Host)" `
                                -Protocol 'https' `
                                -ErrorAction SilentlyContinue | Out-Null
                            New-IISSiteBinding  -Name 'ezcaACME' `
                                -BindingInformation "*:443:$CertificateSubjectName" `
                                -Protocol https `
                                -CertificateThumbPrint $CertificateThumbprint `
                                -CertStoreLocation Cert:\LocalMachine\My `
                                -SslFlag Sni
                        }
                        # $WebBinding.AddSslCertificate($CertificateThumbprint, 'My')
                        # Stop-IISCommitDelay # Commit the IIS changes
                        Write-Verbose "Successfully updated the IIS Site's web binding"
                        $WebBinding = Get-IISSiteBinding -Name "$IISAppName" | Where-Object { $_.Protocol -eq 'https' }
                        Write-Verbose "IIS Site's web binding details (AFTER):"
                        Write-Verbose "$($WebBinding |  Format-Table Cert* | Out-String)"
                    }

                    # Bind the Application Pool to the IIS site
                    Write-Verbose "Binding the Application Pool ($IISAppPoolName) to the IIS site ($IISAppName)"
                    $IISSite.Applications["/"].ApplicationPoolName = $IISAppPoolName
                    Write-Verbose "Successfully bound the Application Pool ($IISAppPoolName) to the IIS site ($IISAppName)"
    
                    # Update the appsettings.json file
                    Write-Verbose "Updating the appsettings.json file with the new ACME Agent instance details"
                    $AppSettingsFileBackup = "$IISrootDirectoryPath\appsettings.json.default" # Added as a default backup during the build stage
                    $AppSettingsFile = "$IISrootDirectoryPath\appsettings.json"
                    if (Test-Path -Path $AppSettingsFile -PathType Leaf) {
                        Remove-Item -Path $AppSettingsFile -Force
                    }
                    Copy-Item -Path $AppSettingsFileBackup -Destination $AppSettingsFile -Force
                    $webAppSettings = Get-Content -Raw -Path $AppSettingsFile
                    $webAppSettings = $webAppSettings.Replace('$SUBJECTNAME$', $CertificateSubjectName).Replace('$AGENTURL$', $URL).Replace('$APPINSIGHTS_CONNECTION_STRING$', $AppInsightsEndpoint)
                    $webAppSettings | Out-File -FilePath $AppSettingsFile -Force
                    Write-Verbose "Successfully updated the appsettings.json file"
                    Write-Verbose (Get-Content -Path $AppSettingsFile | Out-String)
    
                    Stop-IISCommitDelay # Commit the IIS changes

                    # Make sure the Application Pool is recycled to avoid temporary connection issues
                    Write-Verbose "Verifying if we need to recycle the application pool ($IISAppPoolName)"
                    $IISAppPool = Get-IISAppPool -Name $IISAppPoolName -ErrorAction Stop -Debug:$false
                    Write-Verbose "IIS Application Pool details (BEFORE):"
                    Write-Verbose "$($IISAppPool | Format-Table | Out-String)"
                    if ($IISAppPool.State -eq 'Started') {
                        Write-Verbose "Recycling the application pool ($IISAppPoolName)"
                        $IISAppPool.Recycle() | Out-Null
                        Write-Verbose "Sucessfully recycled the application pool"
                    } 
                    # else {
                    #     Write-Verbose "The application pool ($IISAppPoolName) was not started yet, we don't need to recycle it but will start it"
                    #     (Get-IISAppPool -Name $IISAppPoolName -ErrorAction Stop -Debug:$false).Start()
                    #     # $IISAppPool.Start() | Out-Null
                    #     Write-Verbose "Sucessfully started the application pool"    
                    # }
                    Write-Verbose "IIS Application Pool details (AFTER):"
                    $IISAppPool = Get-IISAppPool -Name $IISAppPoolName -ErrorAction Stop -Debug:$false
                    Write-Verbose "$($IISAppPool | Format-Table | Out-String)"
                    
                    # Prewarm the application pool
                    Write-Verbose "Prewarming the application pool ($IISAppPoolName)"
                    try {
                        Invoke-WebRequest -Method GET `
                        -Uri "https://localhost/api/Health/Overall" `
                        -ContentType 'application/json' `
                        -Headers @{ Host = $CertificateSubjectName } `
                        -UseBasicParsing `
                        -ErrorAction SilentlyContinue | Out-Null
                    } catch {
                        Write-Verbose "Prewarming the application pool failed, sleeping for 5 seconds..."
                        Start-Sleep -Seconds 5 # Wait for 5 seconds to allow the application pool to warm up
                    } finally {
                        Write-Verbose "Tried to prewarm the application pool ($IISAppPoolName)"
                    }

                }
            }
            #endregion

            #region Cleanup Stage
            if ($Stages -contains 'Cleanup') {
                if ($PSCmdlet.ShouldProcess("Cleanup", 'Invoke')) {
                    Write-Verbose "### Cleanup Stage ###"
 
                    # Clean up temporary files
                    Write-Verbose "Cleaning up temporary files"
                    Remove-Item -Path $TemporaryDirectoryPath\* -Force -ErrorAction SilentlyContinue
                    Write-Verbose "Successfully cleaned up temporary files"
                }
            }
            #endregion

            #region Health Check Stage
            if ($Stages -contains 'HealthCheck') {
                if ($PSCmdlet.ShouldProcess("Health Check", 'Test')) {
                    Write-Verbose "### Health Check Stage ###"
    
                    # Verify the connection to the ACME Agent's health endpoint
                    Write-Verbose "Verifying the connection to the ACME Agent's health endpoint"
                    $iwrHealthCheck = Invoke-WebRequest -Method GET `
                        -Uri "https://localhost/api/Health/Overall" `
                        -ContentType 'application/json' `
                        -Headers @{ Host = $CertificateSubjectName } `
                        -UseBasicParsing
                    if ($iwrHealthCheck.StatusCode -eq 200) {
                        Write-Verbose "Successfully verified the connection to the ACME Agent's health endpoint"
                        Write-Verbose "$($iwrHealthCheck.Content | ConvertFrom-Json | Format-Table | Out-String)"
                    } else {
                        throw [System.Exception] "Failed to verify the connection to the ACME Agent's health endpoint: $($iwrHealthCheck.StatusCode) - $($iwrHealthCheck.Content)"
                    }
                }
            }
            #endregion

            #region Service Monitor Stage
            if ($Stages -contains 'ServiceMonitor') {
                if ($PSCmdlet.ShouldProcess("Service Monitor", 'Start')) {
                    Write-Verbose "### Service Monitor Stage ###"
                    Write-Verbose "Starting the Service Monitor executable"
                    try {
                        Start-Process -FilePath $ServiceMonitorExecutablePath -ArgumentList 'w3svc', $IISAppPoolName -NoNewWindow -PassThru -Wait -ErrorAction Stop
                    } catch {
                        throw [System.Exception] "Failed to start the Service Monitor executable: $($_.Exception.Message)"
                    }
                }
            }
            #endregion
        }
        catch {
            throw [System.Exception] "An unknown error occurred in the New-KEYTOSACMEAgentInstance function: $($_.Exception.Message)"
        }
    }

    END {
        $ExecutionEndTime = Get-Date
        $ExecutionDuration = $ExecutionEndTime - $ExecutionStartTime
        Write-Verbose "Ending $($MyInvocation.Mycommand) at $ExecutionEndTime"
        Write-Verbose "Execution duration: $ExecutionDuration"
    }
}