function Invoke-MicrosoftGraphConnection {
    param (
        [Parameter(Mandatory = $false)]
        [SecureString]$Credential,
        [Parameter(Mandatory = $false)]
        [string]$Environment = "default"
    )

    # Map environment names to Graph environment values
    $environmentMap = @{
        "USGovGCCHigh" = @{
            URI         = 'graph.microsoft.us'
            Environment = 'USGov'
        }
        "USGovDoD"     = @{
            URI         = 'dod-graph.microsoft.us'
            Environment = 'USGovDoD'
        }
        "GermanyCloud" = @{
            URI         = 'graph.microsoft.com'
            Environment = 'Global'
        }
        "China"        = @{
            URI         = 'microsoftgraph.chinacloudapi.cn'
            Environment = 'China'
        }
        default        = @{
            URI         = 'graph.microsoft.com'
            Environment = 'Global'
        }
    }

    # Determine the Graph environment
    $selectedEnv = $environmentMap[$Environment]
    if (-not $selectedEnv) {
        $selectedEnv = $environmentMap["default"]
    }

    $global:graphURI = $selectedEnv.URI
    $GraphEnvironment = $selectedEnv.Environment

    # Retry logic with a maximum of 3 attempts
    $maxAttempts = 3
    $attempt = 1
    while ($attempt -le $maxAttempts) {
        try {
            Write-Host "Connecting to Microsoft Graph... (Attempt $attempt of $maxAttempts)"

            # Determine the method of connection based on provided parameters
            if ($Credential) {
                Connect-MgGraph -Environment $GraphEnvironment -ContextScope Process -Scopes @(
                    "Directory.Read.All", "RoleManagement.Read.Directory", "DeviceManagementServiceConfig.Read.All",
                    "DeviceManagementConfiguration.Read.All", "User.Read.All", "Policy.Read.All",
                    "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "Group.Read.All",
                    "UserAuthenticationMethod.Read.All", "GroupMember.Read.All", "Organization.Read.All",
                    "Domain.Read.All", "AccessReview.Read.All", "SecurityEvents.Read.All", "AuditLog.Read.All"
                ) -Credential $Credential -ErrorAction Stop | Out-Null
            }
            else {
                Connect-MgGraph -Environment $GraphEnvironment -ContextScope Process -Scopes @(
                    "Directory.Read.All", "RoleManagement.Read.Directory", "DeviceManagementServiceConfig.Read.All",
                    "DeviceManagementConfiguration.Read.All", "User.Read.All", "Policy.Read.All",
                    "DeviceManagementManagedDevices.Read.All", "DeviceManagementApps.Read.All", "Group.Read.All",
                    "UserAuthenticationMethod.Read.All", "GroupMember.Read.All", "Organization.Read.All",
                    "Domain.Read.All", "AccessReview.Read.All", "SecurityEvents.Read.All", "AuditLog.Read.All"
                ) -ErrorAction Stop | Out-Null
            }

            # Verify the connection
            if (-not [string]::IsNullOrEmpty((Get-MgContext))) {
                Write-Host "Connected to Microsoft Graph!" -ForegroundColor DarkYellow -BackgroundColor Black
                $OrgName = (((Get-MgOrganization).VerifiedDomains | Where-Object { $_.Name -like "*.onmicrosoft.com" -and $_.Name -notlike "*mail.onmicrosoft.com" }).Name -split '.onmicrosoft.com')[0]
                return $OrgName
            }
            else {
                throw "Failed to establish a valid context with Microsoft Graph."
            }
        }
        catch {
            Write-Warning "Attempt $attempt failed: $_"
            if ($attempt -ge $maxAttempts) {
                Write-Error "Maximum number of retry attempts reached. Unable to connect to Microsoft Graph."
                throw $_
            }
            Start-Sleep -Seconds 5  # Wait before retrying
			$attempt++
        }
    }
}