#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure ‘User consent for applications’ Is Set To ‘Allow for Verified Publishers’ (Manual)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2013($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2013"
		FindingName	     = "CIS Az 2.13 - User consent for applications is not set to: 'Do not allow user consent' or 'Allow for Verified Publishers'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "12"
		Description	     = "If Microsoft Entra ID is running as an identity provider for third-party applications, permissions and consent should be limited to administrators or pre-approved. Malicious applications may attempt to exfiltrate data or abuse privileged user accounts."
		Remediation	     = "Goto: https://portal.azure.com/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings or Use the PowerShell Command"
		PowerShellScript = 'Import-Module Microsoft.Graph.Identity.SignIns; $params = @{DefaultUserRolePermissions = @{PermissionGrantPoliciesAssigned = @()}}; Update-MgPolicyAuthorizationPolicy -BodyParameter $params'
		DefaultValue	 = "Allow user consent for apps"
		ExpectedValue    = "Do not allow user consent or Allow user consent for apps from verified publishers, for selected permissions"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "4"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Configure how users consent to applications'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/manage-apps/configure-user-consent?pivots=portal#configure-user-consent-to-applications' },
			@{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-protect-and-limit-highly-privileged-users' },
			@{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
			@{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' })
	}
	return $inspectorobject
}

function Audit-CISAz2013
{
	try
	{
		$AffectedOptions = @()
		
		Import-Module Microsoft.Graph.Identity.DirectoryManagement
		# Old Variant
		$UserConsent = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/v1.0/policies/authorizationPolicy")
		
		
		if ($userConsent.defaultUserRolePermissions.permissionGrantPoliciesAssigned -contains "ManagePermissionGrantsForSelf.microsoft-user-default-legacy")
		{
			$finalobject = Build-CISAz2013($userConsent.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
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
return Audit-CISAz2013