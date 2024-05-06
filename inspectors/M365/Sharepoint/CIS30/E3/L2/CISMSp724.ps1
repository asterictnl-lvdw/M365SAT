# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure OneDrive content sharing is restricted 
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMSp724($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp724"
		FindingName	     = "CIS MSp 7.2.4 - Ensure OneDrive content sharing is not restricted !"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "OneDrive, designed for end-user cloud storage, inherently provides less oversight and control compared to SharePoint, which often involves additional content overseers or site administrators. This autonomy can lead to potential risks such as inadvertent sharing of privileged information by end users. Restricting external OneDrive sharing will require users to transfer content to SharePoint folders first which have those tighter controls."
		Remediation	     = "Use the PowerShell Script to enable this setting:"
		PowerShellScript = 'Set-SPOTenant -OneDriveSharingCapability Disabled'
		DefaultValue	 = "ExternalUserAndGuestSharing"
		ExpectedValue    = "ExternalUserSharingOnly or lower"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage sharing settings for SharePoint and OneDrive in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-US/sharepoint/turn-external-sharing-on-or-off?WT.mc_id=365AdminCSH_spo' })
	}
	return $inspectorobject
}

function Audit-CISMSp724
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$SharepointSetting = Get-SPOTenant | Format-List OneDriveSharingCapability
		if ($SharepointSetting.OneDriveSharingCapability -eq "ExternalUserAndGuestSharing")
		{
			$AffectedOptions += "SharingCapability: $($SharepointSetting.OneDriveSharingCapability)"
		}
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp724-SPOTenant.txt"
			$finalobject = Build-CISMSp724($AffectedOptions)
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
return Audit-CISMSp724