function Invoke-MicrosoftAzureConnection {
    param (
        [Parameter(Mandatory = $false)]
        [SecureString]$Credential,
        [Parameter(Mandatory = $false)]
        [string]$Username,
        [Parameter(Mandatory = $false)]
        [string]$Environment = "default"
    )

    # Map environment names to Azure environment values
    $environmentMap = @{
        "USGovGCCHigh" = 'AzureUSGovernment'
        "USGovDoD"     = 'AzureUSGovernment'
        "GermanyCloud" = 'AzureGermanCloud'
        "China"        = 'AzureChinaCloud'
        default        = 'AzureCloud'
    }

    # Determine the Azure environment
    $AzEnvironment = $environmentMap[$Environment]
    if (-not $AzEnvironment) {
        $AzEnvironment = $environmentMap["default"]
    }

    # Retry logic with a maximum of 3 attempts
    $maxAttempts = 3
    $attempt = 1
    while ($attempt -le $maxAttempts) {
        
        try {
            Write-Host "Connecting to Microsoft Azure PowerShell... (Attempt $attempt of $maxAttempts)"

            # Determine the method of connection based on provided parameters
            if ($Credential) {
                Connect-AzAccount -Environment $AzEnvironment -Credential $Credential -ErrorAction Stop | Out-Null
            }
            elseif ($Username) {
                Connect-AzAccount -AccountId $Username -Environment $AzEnvironment -ErrorAction Stop | Out-Null
            }
            else {
                Connect-AzAccount -Environment $AzEnvironment -ErrorAction Stop | Out-Null
            }

            # Verify the connection
            if (-not [string]::IsNullOrEmpty((Get-AzContext))) {
                Write-Host "Connected to Microsoft Azure PowerShell!" -ForegroundColor DarkYellow -BackgroundColor Black
                return $true
            }
            else {
                throw "Failed to establish a valid context with Microsoft Azure."
            }
        }
        catch {
            Write-Warning "Attempt $attempt to connect Microsoft Azure PowerShell failed!"
            if ($attempt -ge $maxAttempts) {
                Write-Error "Maximum number of retry attempts reached. Unable to connect to Azure."
                throw $_
				#break
            }
            Start-Sleep -Seconds 5  # Wait before retrying
			$attempt++
        }
    }
}