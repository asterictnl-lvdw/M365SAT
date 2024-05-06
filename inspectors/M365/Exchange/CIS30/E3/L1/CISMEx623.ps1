# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure email from external senders is identified
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx623($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx623"
		FindingName	     = "CIS MEx 6.2.3 - Email from external senders cannot be identified"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "10"
		Description	     = "Tagging emails from external senders helps to inform end users about the origin of the email. This can allow them to proceed with more caution and make informed decisions when it comes to identifying spam or phishing emails."
		Remediation	     = "Use the PowerShell script to enable CustomerLockBox for your Exchange Tenant"
		PowerShellScript = 'Set-ExternalInOutlook -Enabled $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Native external sender callouts on email in Outlook'; 'URL' = "https://techcommunity.microsoft.com/t5/exchange-team-blog/native-external-sender-callouts-on-email-in-outlook/ba-p/2250098" })
	}
	return $inspectorobject
}

function Audit-CISMEx623
{
	try
	{
		$Violation = @()
		$ExternalSenderValidation = Get-ExternalInOutlook
		foreach ($Validation in $ExternalSenderValidation)
		{
			if ($Validation.Enabled -ne $True -or -not [string]::IsNullOrEmpty($Validation.AllowList))
			{
				$Violation += "$($Validation.Identity): $($Validation.Enabled)"
			}
		}
		
		if ($Violation.Count -igt 0)
		{
			$domainwlrules | Format-List | Out-File -FilePath "$path\CISMEx623-ExternalInOutlook.txt"
			$endobject = Build-CISMEx623($Violation)
			return $endobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx623