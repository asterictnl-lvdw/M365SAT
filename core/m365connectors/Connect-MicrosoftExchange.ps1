function Invoke-MicrosoftExchangeConnection {
    param (
        [Parameter(Mandatory = $false)]
        [SecureString]$Credential,
        [Parameter(Mandatory = $false)]
        [string]$Username,
        [Parameter(Mandatory = $false)]
        [string]$Environment = "default"
    )

    # Map environment names to Exchange environment values
    $environmentMap = @{
        "USGovGCCHigh" = 'O365USGovGCCHigh'
        "USGovDoD"     = 'O365USGovDoD'
        "GermanyCloud" = 'O365GermanyCloud'
        "China"        = 'O365China'
        default        = 'O365Default'
    }

    # Determine the Exchange environment
    $ExEnvironment = $environmentMap[$Environment]
    if (-not $ExEnvironment) {
        $ExEnvironment = $environmentMap["default"]
    }

    # Retry logic with a maximum of 3 attempts
    $maxAttempts = 3
    $attempt = 1
    while ($attempt -le $maxAttempts) { 
        try {
            Write-Host "Connecting to Microsoft Exchange... (Attempt $attempt of $maxAttempts)"

            # Determine the method of connection based on provided parameters
            if ($Credential) {
                Connect-ExchangeOnline -DisableWAM -ExchangeEnvironmentName $ExEnvironment -Credential $Credential -ShowBanner:$false -ErrorAction Stop | Out-Null
            }
            elseif ($Username) {
                Connect-ExchangeOnline -DisableWAM -ExchangeEnvironmentName $ExEnvironment -UserPrincipalName $Username -ShowBanner:$false -ErrorAction Stop | Out-Null
            }
            else {
                Connect-ExchangeOnline -DisableWAM -ExchangeEnvironmentName $ExEnvironment -ShowBanner:$false -ErrorAction Stop | Out-Null
            }

            # Verify the connection
            if (-not [string]::IsNullOrEmpty((Get-ConnectionInformation))) {
                $OrgName = ((Get-AcceptedDomain | Where-Object { $_.DomainName -like "*.onmicrosoft.com" -and $_.DomainName -notlike "*mail.onmicrosoft.com" }).DomainName -split '.onmicrosoft.com')[0]
                Write-Host "Connected to Microsoft Exchange!" -ForegroundColor DarkYellow -BackgroundColor Black
                return $OrgName
            }
            else {
                throw "Failed to establish a valid connection with Microsoft Exchange."
            }
        }
        catch {
            Write-Warning "Attempt $attempt failed: $_"
            if ($attempt -ge $maxAttempts) {
                Write-Error "Maximum number of retry attempts reached. Unable to connect to Microsoft Exchange."
                throw $_
            }
            Start-Sleep -Seconds 5  # Wait before retrying
			$attempt++
        }
    }
}