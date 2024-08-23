function Invoke-MicrosoftSharepointCredentials
{
	param(
		[string]$TenantName,
		[System.Object]$Credential,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$SpEnvironment = 'ITAR' 
			}
			"USGovDoD" 
			{ 
				$SpEnvironment = 'ITAR' 
			}
			"GermanyCloud" 
			{ 
				$SpEnvironment = 'Germany' 
			}
			"China" 
			{ 
				$SpEnvironment = 'China' 
			}
			default 
			{ 
				$SpEnvironment = 'default'
			}
		}

		Write-Host "Connecting to Microsoft Sharepoint Powershell..."
		Connect-SPOService -Url "https://$TenantName.sharepoint.com" -Region $SpEnvironment -Credential $Credential -ErrorAction Stop
		if ((Get-SPOTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft Sharepoint Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftSharepointUsername
{
	param(
		[string]$TenantName,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$SpEnvironment = 'ITAR' 
			}
			"USGovDoD" 
			{ 
				$SpEnvironment = 'ITAR' 
			}
			"GermanyCloud" 
			{ 
				$SpEnvironment = 'Germany' 
			}
			"China" 
			{ 
				$SpEnvironment = 'China' 
			}
			default 
			{ 
				$SpEnvironment = 'default'
			}
		}

		Write-Host "Connecting to Microsoft Sharepoint Powershell..."
		Connect-SPOService -Url "https://$TenantName.sharepoint.com" -Region $SpEnvironment -ErrorAction Stop
		if ((Get-SPOTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft Sharepoint Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftSharepointLite
{
	param(
		[string]$TenantName,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$SpEnvironment = 'ITAR' 
			}
			"USGovDoD" 
			{ 
				$SpEnvironment = 'ITAR' 
			}
			"GermanyCloud" 
			{ 
				$SpEnvironment = 'Germany' 
			}
			"China" 
			{ 
				$SpEnvironment = 'China' 
			}
			default 
			{ 
				$SpEnvironment = 'default'
			}
		}

		Write-Host "Connecting to Microsoft Sharepoint Powershell..."
		Connect-SPOService -Url "https://$TenantName.sharepoint.com" -Region $SpEnvironment -ErrorAction Stop
		if ((Get-SPOTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft Sharepoint Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Sharepoint Powershell' -ErrorRecord $_
		return $false
	}
	
}