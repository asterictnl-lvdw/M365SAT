# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure reauthentication with verification code is restricted
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMSp7210($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp7210"
		FindingName	     = "CIS MSp 7.2.10 - Reauthentication with verification code is not restricted!"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "By increasing the frequency of times guests need to reauthenticate this ensures guest user access to data is not prolonged beyond an acceptable amount of time."
		Remediation	     = "Use the PowerShell Script to enable this setting:"
		PowerShellScript = 'Set-SPOTenant -EmailAttestationRequired $true -EmailAttestationReAuthDays 15'
		DefaultValue	 = "False and 30"
		ExpectedValue    = "True and 15"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Secure external sharing recipient experience'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/what-s-new-in-sharing-in-targeted-release' },
		@{ 'Name' = 'Manage sharing settings for SharePoint and OneDrive in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/turn-external-sharing-on-or-off#change-the-organization-level-external-sharing-setting' },
		@{ 'Name' = 'Email one-time passcode authentication'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/one-time-passcode' })
	}
	return $inspectorobject
}

function Audit-CISMSp7210
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$SharepointSetting = Get-SPOTenant | Format-Table  EmailAttestationRequired, EmailAttestationReAuthDays
		if ($SharepointSetting.EmailAttestationRequired -ne $True)
		{
			$AffectedOptions += "EmailAttestationRequired: False"
		}
		if ($SharepointSetting.EmailAttestationReAuthDays -igt 15)
		{
			$AffectedOptions += "EmailAttestationReAuthDays: $($SharepointSetting.EmailAttestationReAuthDays)"
		}
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp7210-SPOTenant.txt"
			$finalobject = Build-CISMSp7210($AffectedOptions)
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
return Audit-CISMSp7210