# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Safe Links for Office Applications is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx215($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx215"
		FindingName	     = "CIS MEx 2.1.5 - Safe Attachments for Office Applications is not Enabled!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "10"
		Description	     = "Safe Attachments for SharePoint, OneDrive, and Microsoft Teams protects organizations from inadvertently sharing malicious files. When a malicious file is detected, that file is blocked so that no one can open, copy, move, or share it until further actions are taken by the organization's security team."
		Remediation	     = "Use the PowerShell Script to create and apply the policy within your organization."
		PowerShellScript = 'Set-AtpPolicyForO365 -EnableATPForSPOTeamsODB $true -EnableSafeDocs $true -AllowSafeDocsOpen $false'
		DefaultValue	 = "Undefined"
		ExpectedValue    = "EnableATPForSPOTeamsODB: True EnableSafeDocs: True AllowSafeDocsOpen: False"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Security defaults in Azure AD'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults' },
		@{ 'Name' = 'Introducing security defaults'; 'URL' = 'https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/introducing-security-defaults/ba-p/1061414' },
	@{ 'Name' = 'IM-2: Protect identity and authentication systems'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-2-protect-identity-and-authentication-systems' })
}
	return $inspectorobject
}

function Audit-CISMEx215
{
	$AffectedSettings = @()
	try
	{
		# Actual Script
		try
		{
			$Policies = Get-AtpPolicyForO365 | fl Name, EnableATPForSPOTeamsODB,EnableSafeDocs,AllowSafeDocsOpen
			
			if ($Settings.EnableATPForSPOTeamsODB -eq $False)
			{
				$AffectedSettings += "$($Policies.Name): EnableATPForSPOTeamsODB: $($Settings.EnableATPForSPOTeamsODB)"
			}
			if ($Settings.EnableSafeDocks -eq $False)
			{
				$AffectedSettings += "$($Policies.Name): EnableSafeDocks: $($Settings.EnableSafeDocks)"
			}
			if ($Settings.AllowSafeDocsOpen -ne $False)
			{
				$AffectedSettings += "$($Policies.Name): AllowSafeDocsOpen: $($Settings.AllowSafeDocsOpen)"
			}
			
		}
		catch
		{
			$AffectedSettings += "ATP Policy is not working!"
		}
		
		# Validation
		if ($AffectedSettings.Count -igt 0)
		{
			$AffectedSettings | Format-Table -AutoSize | Out-File "$path\CISMEx215ATPPolicySettings.txt"
			$finalobject = Build-CISMEx215($AffectedSettings)
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
return Audit-CISMEx215