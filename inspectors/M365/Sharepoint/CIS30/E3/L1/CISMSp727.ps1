# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure link sharing is restricted in SharePoint and OneDrive
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMSp727($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp727"
		FindingName	     = "CIS MSp 7.2.7 - Ensure link sharing is not restricted in SharePoint and OneDrive!"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "By defaulting to specific people, the user will first need to consider whether or not the content being shared should be accessible by the entire organization versus select individuals. This aids in reinforcing the concept of least privilege."
		Remediation	     = "Use the PowerShell Script to enable this setting:"
		PowerShellScript = 'Set-SPOTenant -DefaultSharingLinkType Direct'
		DefaultValue	 = "Internal"
		ExpectedValue    = "Direct"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Reference - Set-SPOTenant'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' })
	}
	return $inspectorobject
}

function Audit-CISMSp727
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$SharepointSetting = Get-SPOTenant | Format-Table LegacyAuthProtocolsEnabled, LegacyBrowserAuthProtocolsEnabled
		if ($SharepointSetting.DefaultSharingLinkType -eq "Internal")
		{
			$AffectedOptions += "DefaultSharingLinkType: $($SharepointSetting.DefaultSharingLinkType)"
		}
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp727-SPOTenant.txt"
			$finalobject = Build-CISMSp727($AffectedOptions)
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
return Audit-CISMSp727