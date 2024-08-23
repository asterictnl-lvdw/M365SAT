function Invoke-MicrosoftSecurityComplianceCredentials
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
				$IPPSEnvironment = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.us/common' 
			}
			"USGovDoD" 
			{ 
				$IPPSEnvironment = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.us/common' 
			}
			"GermanyCloud" 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/' 
				$AADUri = 'https://login.microsoftonline.com/common' 
			}
			"China" 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.partner.outlook.cn/powershell-liveid'
				$AADUri = 'https://login.chinacloudapi.cn/common' 
			}
			default 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.com/common' 
			}
		}

		Write-Host "Connecting to Microsoft Security & Compliance..."
		Connect-IPPSSession -ConnectionUri $IPPSEnvironment -AzureADAuthorizationEndpointUri $AADUri -Credential $Credential -ShowBanner:$false -ErrorAction Stop
 		$Result = Get-PolicyConfig
		if ($?)
		{
			Write-Host "Connected to Microsoft Security & Compliance!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Security & Compliance' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Security & Compliance' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftSecurityComplianceUsername
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
				$IPPSEnvironment = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.us/common' 
			}
			"USGovDoD" 
			{ 
				$IPPSEnvironment = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.us/common' 
			}
			"GermanyCloud" 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/' 
				$AADUri = 'https://login.microsoftonline.com/common' 
			}
			"China" 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.partner.outlook.cn/powershell-liveid'
				$AADUri = 'https://login.chinacloudapi.cn/common' 
			}
			default 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.com/common' 
			}
		}

		Write-Host "Connecting to Microsoft Security & Compliance..."
		Connect-IPPSSession -ConnectionUri $IPPSEnvironment -AzureADAuthorizationEndpointUri $AADUri -UserPrincipalName $Username -ShowBanner:$false -ErrorAction Stop
		$Result = Get-PolicyConfig
		if ($?)
		{
			Write-Host "Connected to Microsoft Security & Compliance!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $true
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Security & Compliance' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Security & Compliance' -ErrorRecord $_
		return $false
	}
	
}

function Invoke-MicrosoftSecurityComplianceLite
{
	param(
		[string]$Environment
	)

	try
	{
		switch ($Environment) {
			"USGovGCCHigh" 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.office365.us/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.us/common' 
			}
			"USGovDoD" 
			{ 
				$IPPSEnvironment = 'https://l5.ps.compliance.protection.office365.us/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.us/common' 
			}
			"GermanyCloud" 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/' 
				$AADUri = 'https://login.microsoftonline.com/common' 
			}
			"China" 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.partner.outlook.cn/powershell-liveid'
				$AADUri = 'https://login.chinacloudapi.cn/common' 
			}
			default 
			{ 
				$IPPSEnvironment = 'https://ps.compliance.protection.outlook.com/powershell-liveid/'
				$AADUri = 'https://login.microsoftonline.com/common' 
			}
		}

		Write-Host "Connecting to Microsoft Security & Compliance..."
		Connect-IPPSSession -ConnectionUri $IPPSEnvironment -AzureADAuthorizationEndpointUri $AADUri -ShowBanner:$false -ErrorAction Stop
		$Result = Get-PolicyConfig
		if ($?)
		{
			$OrgName = ((Get-AcceptedDomain |  Where-Object {  { $_.Default -eq 'True' } -and ($_.DomainName -like "*.onmicrosoft.com") -and ($_.DomainName -notlike "*mail.onmicrosoft.com") }).DomainName -split '.onmicrosoft.com')[0]
			Write-Host "Connected to Microsoft Security & Compliance!" -ForegroundColor DarkYellow -BackgroundColor Black
			return $OrgName
		}
		else
		{
			Write-ErrorLog 'Failed to Connect to Microsoft Security & Compliance' -ErrorRecord $_
			return $false
		}
	}
	catch
	{
		Write-ErrorLog 'Failed to Connect to Microsoft Security & Compliance' -ErrorRecord $_
		return $false
	}
	
}