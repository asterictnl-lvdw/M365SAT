function Invoke-MicrosoftSecurityComplianceCredentials($Credential)
{
	try
	{
		Write-Host "Connecting to Microsoft Security & Compliance..."
		Connect-IPPSSession -Credential $Credential -ShowBanner:$false -ErrorAction Stop
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

function Invoke-MicrosoftSecurityComplianceUsername($Username)
{
	try
	{
		Write-Host "Connecting to Microsoft Security & Compliance..."
		Connect-IPPSSession -UserPrincipalName $Username -ShowBanner:$false -ErrorAction Stop
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
	try
	{
		Write-Host "Connecting to Microsoft Security & Compliance..."
		Connect-IPPSSession -ShowBanner:$false -ErrorAction Stop
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