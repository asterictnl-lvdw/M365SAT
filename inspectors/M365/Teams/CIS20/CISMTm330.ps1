# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Teams
# Purpose: Ensure 'external access' is restricted in the Teams admin center
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMTm330($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMTm330"
		FindingName	     = "CISM Tm 3.3 - External access is not restricted in the Teams admin center!"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "8"
		Description	     = "Allowing users to communicate with Skype or Teams users outside of an organization presents a potential security threat as external users can interact with organization users over Skype for Business or Teams. While legitimate, productivity-improving scenarios exist, they are outweighed by the risk of data loss, phishing, and social engineering attacks against organization users via Teams. Therefore, it is recommended to restrict external communications in order to minimize the risk of security incidents."
		Remediation	     = "Use the PowerShell script to disallow External Access"
		PowerShellScript = 'Set-CsTenantFederationConfiguration -AllowTeamsConsumer $false -AllowPublicUsers $false -AllowFederatedUsers $false'
		DefaultValue	 = "All True"
		ExpectedValue    = "All False"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "4"
		RiskRating	     = "Medium"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Manage external meetings and chat with people and organizations using Microsoft identities'; 'URL' = "https://learn.microsoft.com/en-US/microsoftteams/trusted-organizations-external-meetings-chat?WT.mc_id=TeamsAdminCenterCSH&tabs=organization-settings" })
	}
	return $inspectorobject
}

function Audit-CISMTm330
{
	try
	{
		$ViolatedTeamsSettings = @()
		$TeamsExternalAccess = Get-CsTenantFederationConfiguration
		if ($TeamsExternalAccess.AllowTeamsConsumer -eq $True)
		{
			$ViolatedTeamsSettings += "AllowTeamsConsumer: True"
		}
		if ($TeamsExternalAccess.AllowPublicUsers -eq $True)
		{
			$ViolatedTeamsSettings += "AllowPublicUsers: True"
		}
		if ($TeamsExternalAccess.AllowFederatedUsers -eq $True)
		{
			$ViolatedTeamsSettings += "AllowFederatedUsers: True"
		}
		if ($TeamsExternalAccess.AllowedDomains.count -lt 1 -or $TeamsExternalAccess.AllowedDomains -eq "AllowAllKnownDomains")
		{
			$ViolatedTeamsSettings += "AllowedDomains: $($TeamsExternalAccess.AllowedDomains)"
		}
		if ($ViolatedTeamsSettings.Count -igt 0)
		{
			$endobject = Build-CISMTm330($ViolatedTeamsSettings)
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
return Audit-CISMTm330