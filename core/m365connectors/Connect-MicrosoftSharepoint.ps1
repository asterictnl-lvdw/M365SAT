function Invoke-MicrosoftSharepointPnPConnection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantName,

        [Parameter(Mandatory = $false)]
        [SecureString]$Credential,

        [Parameter(Mandatory = $false)]
        [string]$Environment = "Production"
    )

    # Map environment names to SharePoint environment values
    $environmentMap = @{
        "USGovGCCHigh" = "USGovernmentHigh"
        "USGovDoD"     = "USGovernmentDoD"
        "GermanyCloud" = "Germany"
        "China"        = "China"
        default        = "Production"
    }

    # Determine the SharePoint environment
    $SpEnvironment = $environmentMap[$Environment]
    if (-not $SpEnvironment) {
        $SpEnvironment = $environmentMap["default"]
    }

    # Retry logic with a maximum of 3 attempts
    $maxAttempts = 3
    $attempt = 1
    while ($attempt -le $maxAttempts) {
        try {
            Write-Host "Connecting to Microsoft PnP PowerShell... (Attempt $attempt of $maxAttempts)"

            # Register or retrieve the ClientId for the app
            if ($null -ne ((Get-MgApplication | Where-Object { $_.DisplayName -eq 'PnP Rocks' }).AppId)){
                $ClientId = (Get-MgApplication | Where-Object { $_.DisplayName -eq 'PnP Rocks' }).AppId
            }
            else{
                Write-Host "Creating EntraIDAppRegistration for PnP.PowerShell..."
                $ClientId = Register-PnPEntraIDAppForInteractiveLogin -ApplicationName "PnP Rocks" -Tenant "$TenantName.onmicrosoft.com" -Interactive -AzureEnvironment $SpEnvironment -ErrorAction SilentlyContinue
                $ClientId = $ClientId.'AzureAppId/ClientId'
            }

            # Determine the method of connection based on provided parameters
            if ($Credential) {
                Connect-PnPOnline -AzureEnvironment $SpEnvironment -Url "https://$TenantName.sharepoint.com" -Credential $Credential -ClientId $ClientId -ErrorAction Stop | Out-Null
            }
            else {
                Connect-PnPOnline -AzureEnvironment $SpEnvironment -Url "https://$TenantName.sharepoint.com" -Interactive -ClientId $ClientId -ErrorAction Stop | Out-Null
            }

            # Verify the connection
            if (-not [string]::IsNullOrEmpty((Get-PnPConnection))) {
                Write-Host "Connected to Microsoft PnP PowerShell!" -ForegroundColor DarkYellow -BackgroundColor Black
                return $true
            }
            else {
                throw "Failed to establish a valid context with Microsoft PnP PowerShell."
            }
        }
        catch {
            Write-Warning "Attempt $attempt failed: $_"
            if ($attempt -ge $maxAttempts) {
                Write-Error "Maximum number of retry attempts reached. Unable to connect to Microsoft PnP PowerShell."
                throw $_
            }
            Start-Sleep -Seconds 5  # Wait before retrying
			$attempt++
        }
    }
}

function Invoke-MicrosoftSharepointSPOServiceConnection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantName,
        [Parameter(Mandatory = $false)]
        [SecureString]$Credential,
        [Parameter(Mandatory = $false)]
        [string]$Environment = "default"
    )

    # Map environment names to SharePoint environment values
    $environmentMap = @{
        "USGovGCCHigh" = "ITAR"
        "USGovDoD"     = "ITAR"
        "GermanyCloud" = "Germany"
        "China"        = "China"
        default        = "default"
    }

    # Determine the SharePoint environment
    $SpEnvironment = $environmentMap[$Environment]
    if (-not $SpEnvironment) {
        $SpEnvironment = $environmentMap["default"]
    }

    # Retry logic with a maximum of 3 attempts
    $maxAttempts = 3
    $attempt = 1
    while ($attempt -le $maxAttempts) {

        try {
            Write-Host "Connecting to Microsoft SharePoint SPOService... (Attempt $attempt of $maxAttempts)"

            # Determine the method of connection based on provided parameters
            if ($Credential) {
                Connect-SPOService -Url "https://$TenantName-admin.sharepoint.com" -Region $SpEnvironment -Credential $Credential -ErrorAction Stop | Out-Null
            }
            else {
                Connect-SPOService -Url "https://$TenantName-admin.sharepoint.com" -Region $SpEnvironment -ErrorAction Stop | Out-Null
            }

            # Verify the connection
            if ($null -ne (Get-SPOTenant)) {
                Write-Host "Connected to Microsoft SharePoint SPOService!" -ForegroundColor DarkYellow -BackgroundColor Black
                return $true
            }
            else {
                throw "Failed to establish a valid context with Microsoft SharePoint SPOService."
            }
        }
        catch {
            Write-Warning "Attempt $attempt failed: $_"
            if ($attempt -ge $maxAttempts) {
                Write-Error "Maximum number of retry attempts reached. Unable to connect to Microsoft SharePoint SPOService."
                throw $_
            }
            Start-Sleep -Seconds 5  # Wait before retrying
			$attempt++
        }
    }
}