# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure external content sharing is restricted
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMSp723($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMSp723"
		FindingName	     = "CIS MSp 7.2.3 - External content sharing is not restricted!"
		ProductFamily    = "Microsoft Sharepoint"
		RiskScore	     = "15"
		Description	     = "Forcing guest authentication on the organization's tenant enables the implementation of controls and oversight over external file sharing. When a guest is registered with the organization, they now have an identity which can be accounted for. This identity can also have other restrictions applied to it through group membership and conditional access rules."
		Remediation	     = "Use the PowerShell Script to enable Modern Authentication for Microsoft Exchange Online."
		PowerShellScript = 'Set-SPOTenant -SharingCapability ExternalUserSharingOnly'
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

function Audit-CISMSp723
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$SharepointSetting = Get-SPOTenant | Format-List SharingCapability
		if ($SharepointSetting.SharingCapability -eq "ExternalUserAndGuestSharing")
		{
			$AffectedOptions += "SharingCapability: $($SharepointSetting.SharingCapability)"
		}
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$SharepointSetting | Format-Table -AutoSize | Out-File "$path\CISMSp723-SPOTenant.txt"
			$finalobject = Build-CISMSp723($AffectedOptions)
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
return Audit-CISMSp723