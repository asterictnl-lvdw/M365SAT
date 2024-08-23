function Invoke-MicrosoftExchangeCredentials
{
	param(
		[System.Object]$Credential,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{
				$ExEnvironment = 'O365USGovGCCHigh' 
			}
			"USGovDoD"
			{ 
				$ExEnvironment = 'O365USGovDoD'
			}
			"GermanyCloud" 
			{ 
				$ExEnvironment = 'O365GermanyCloud' 
			}
			"China" 
			{ 
				$ExEnvironment = 'O365China' 
			}
			default 
			{ 
				$ExEnvironment = 'O365Default' 
			}
		}

		Write-Host "Connecting to Microsoft Exchange..."
		Connect-ExchangeOnline -ExchangeEnvironmentName $ExEnvironment -Credential $Credential -ShowBanner:$false -ErrorAction Stop
		if ((Get-ConnectionInformation) -ne $null)
		{
			$OrgName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
			Write-Host "Connected to Microsoft Exchange!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $OrgName
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftExchangeUsername
{
	param(
		[string]$Username,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{
				$ExEnvironment = 'O365USGovGCCHigh' 
			}
			"USGovDoD"
			{ 
				$ExEnvironment = 'O365USGovDoD'
			}
			"GermanyCloud" 
			{ 
				$ExEnvironment = 'O365GermanyCloud' 
			}
			"China" 
			{ 
				$ExEnvironment = 'O365China' 
			}
			default 
			{ 
				$ExEnvironment = 'O365Default' 
			}
		}

		Write-Host "Connecting to Microsoft Exchange..."
		Connect-ExchangeOnline -ExchangeEnvironmentName $ExEnvironment -UserPrincipalName $Username -ShowBanner:$false
		if ((Get-ConnectionInformation) -ne $null)
		{
			$OrgName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
			Write-Host "Connected to Microsoft Exchange!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $OrgName
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftExchangeLite
{
	param(
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{
				$ExEnvironment = 'O365USGovGCCHigh' 
			}
			"USGovDoD"
			{ 
				$ExEnvironment = 'O365USGovDoD'
			}
			"GermanyCloud" 
			{ 
				$ExEnvironment = 'O365GermanyCloud' 
			}
			"China" 
			{ 
				$ExEnvironment = 'O365China' 
			}
			default 
			{ 
				$ExEnvironment = 'O365Default' 
			}
		}

		Write-Host "Connecting to Microsoft Exchange..."
		Connect-ExchangeOnline -ShowBanner:$false -ExchangeEnvironmentName $ExEnvironment
		if ((Get-ConnectionInformation) -ne $null)
		{
			$OrgName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
			Write-Host "Connected to Microsoft Exchange!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $OrgName
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Exchange' -ErrorRecord $_
		return $false
	}
	
}