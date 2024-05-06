# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure modern authentication for SharePoint applications is required
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMSp721($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp721"
		FindingName	     = "CIS MSp 7.2.1 - Modern Authentication for Microsoft Sharepoint is disabled!"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "Strong authentication controls, such as the use of multifactor authentication, may be circumvented if basic authentication is used by SharePoint applications. Requiring modern authentication for SharePoint applications ensures strong authentication mechanisms are used when establishing sessions between these applications, SharePoint, and connecting users."
		Remediation	     = "Use the PowerShell Script to enable Modern Authentication for Microsoft Exchange Online."
		PowerShellScript = 'Set-SPOTenant -LegacyAuthProtocolsEnabled $false -LegacyBrowserAuthProtocolsEnabled $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Reference - Set-SPOTenant'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' })
	}
	return $inspectorobject
}

function Audit-CISMSp721
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$SharepointSetting = Get-SPOTenant | Format-Table LegacyAuthProtocolsEnabled, LegacyBrowserAuthProtocolsEnabled
		if ($SharepointSetting.LegacyAuthProtocolsEnabled -ne $False)
		{
			$AffectedOptions += "LegacyAuthProtocolsEnabled: True"
		}
		if ($SharepointSetting.LegacyBrowserAuthProtocolsEnabled -ne $false)
		{
			$AffectedOptions += "LegacyBrowserAuthProtocolsEnabled: True"
		}
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp721-SPOTenant.txt"
			$finalobject = Build-CISMSp721($AffectedOptions)
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
return Audit-CISMSp721