function Invoke-MicrosoftSharepointPnPCredentials{
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
				$SpEnvironment = 'USGovernmentHigh' 
			}
			"USGovDoD" 
			{ 
				$SpEnvironment = 'USGovernmentDoD' 
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
				$SpEnvironment = 'Production'
			}
		}
		$ClientId = Register-PnPEntraIDAppForInteractiveLogin -ApplicationName "PnP Rocks" -Tenant $TenantName.onmicrosoft.com -Credential $Credential
		$ClientId = $ClientId.'AzureAppId/ClientId'
		if ([string]::IsNullOrEmpty($ClientId)){
			$ClientId =  (Get-MgApplication | Where-Object {$_.DisplayName -eq 'PnP Rocks'}).AppId
		}
		$Connection = Connect-PnPOnline -AzureEnvironment $Environment -Url "https://$TenantName.sharepoint.com" -Credential $Credential -ClientId $ClientId
		if ((Get-PnPTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft PnP Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft PnP Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft PnP Powershell' -ErrorRecord $_
		return $false
	}
}

function Invoke-MicrosoftSharepointPnPUsername{
	param(
		[string]$TenantName,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$SpEnvironment = 'USGovernmentHigh' 
			}
			"USGovDoD" 
			{ 
				$SpEnvironment = 'USGovernmentDoD' 
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
				$SpEnvironment = 'Production'
			}
		}
		$ClientId = Register-PnPEntraIDAppForInteractiveLogin -ApplicationName "PnP Rocks" -Tenant $TenantName.onmicrosoft.com -Interactive
		$ClientId = $ClientId.'AzureAppId/ClientId'
		if ([string]::IsNullOrEmpty($ClientId)){
			$ClientId =  (Get-MgApplication | Where-Object {$_.DisplayName -eq 'PnP Rocks'}).AppId
		}
		$Connection = Connect-PnPOnline -AzureEnvironment $Environment -Url "https://$TenantName.sharepoint.com" -Interactive -ClientId $ClientID
		if ((Get-PnPTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft PnP Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft PnP Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft PnP Powershell' -ErrorRecord $_
		return $false
	}
}

function Invoke-MicrosoftSharepointPnPLite{
	param(
		[string]$TenantName,
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$SpEnvironment = 'USGovernmentHigh' 
			}
			"USGovDoD" 
			{ 
				$SpEnvironment = 'USGovernmentDoD' 
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
				$SpEnvironment = 'Production'
			}
		}
		$ClientId = Register-PnPEntraIDAppForInteractiveLogin -ApplicationName "PnP Rocks" -Tenant $TenantName.onmicrosoft.com -Interactive
		$ClientId = $ClientId.'AzureAppId/ClientId'
		if ([string]::IsNullOrEmpty($ClientId)){
			$ClientId =  (Get-MgApplication | Where-Object {$_.DisplayName -eq 'PnP Rocks'}).AppId
		}
		$Connection = Connect-PnPOnline -AzureEnvironment $Environment -Url "https://$TenantName.sharepoint.com" -Interactive -ClientId $ClientID
		if ((Get-PnPTenant) -ne $null)
		{
			Write-Host "Connected to Microsoft PnP Powershell!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft PnP Powershell' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft PnP Powershell' -ErrorRecord $_
		return $false
	}
}

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
		Connect-SPOService -Url "https://$TenantName-admin.sharepoint.com" -Region $SpEnvironment -Credential $Credential -ErrorAction Stop
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
		Connect-SPOService -Url "https://$TenantName-admin.sharepoint.com" -Region $SpEnvironment -ErrorAction Stop
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
		Connect-SPOService -Url "https://$TenantName-admin.sharepoint.com" -Region $SpEnvironment -ErrorAction Stop
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