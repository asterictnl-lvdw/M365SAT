# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure modern authentication for Exchange Online is enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMEx120($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx120"
		FindingName	     = "CIS MEx 1.2 - Modern Authentication for Exchange Online is disabled!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "3"
		Description	     = "Strong authentication controls, such as the use of multifactor authentication, may be circumvented if basic authentication is used by Exchange Online email clients such as Outlook 2016 and Outlook 2013. Enabling modern authentication for Exchange Online ensures strong authentication mechanisms are used when establishing sessions between email clients and Exchange Online."
		Remediation	     = "Use the PowerShell Script to enable Modern Authentication for Microsoft Exchange Online."
		PowerShellScript = 'Set-OrganizationConfig -OAuth2ClientProfileEnabled $True'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Enable or disable modern authentication in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online" },
			@{ 'Name' = 'Set-OrganizationConfig Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-organizationconfig?view=exchange-ps" })
	}
	return $inspectorobject
}

function Audit-CISMEx120
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$ExchangeSetting = Get-OrganizationConfig | Format-Table -Auto Name, OAuth2ClientProfileEnabled
		ForEach ($Organization in $ExchangeSetting)
		{
			if ($ExchangeSetting.OAuth2ClientProfileEnabled -ne $true)
			{
				$AffectedOptions += "$($ExchangeSetting.Name): OAuth2ClientProfileEnabled is: $($ExchangeSetting.OAuth2ClientProfileEnabled)"
			}
		}
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$finalobject = Build-CISMEx120($AffectedOptions)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx120