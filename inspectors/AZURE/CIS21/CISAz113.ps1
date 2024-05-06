# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure That ‘Users Can Register Applications’ Is Set to ‘No’ (Manual)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1130($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1130"
		FindingName	     = "CIS Az 1.13 - Users Can Register Applications Is Set to 'Yes'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "It is recommended to only allow an administrator to register custom-developed applications. This ensures that the application undergoes a formal security review and approval process prior to exposing Microsoft Entra ID data. Certain users like developers or other high-request users may also be delegated permissions to prevent them from waiting on an administrative user. Your organization should review your policies and decide your needs."
		Remediation	     = "Use the PowerShell Script to enable Security Defaults on Microsoft Entra ID"
		PowerShellScript = 'Import-Module Microsoft.Graph.Identity.SignIns; $params = @{AllowedToCreateApps = $false}; Update-MgPolicyAuthorizationPolicy -BodyParameter $params'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Restrict who can create applications'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/delegate-app-roles#restrict-who-can-create-applications' },
			@{ 'Name' = 'Who has permission to add applications to my Azure AD instance?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity-platform/how-applications-are-added#who-has-permission-to-add-applications-to-my-azure-ad-instance' },
			@{ 'Name' = 'GS-1: Align organization roles, responsibilities and accountabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-1-define-asset-management-and-data-protection-strategy' },
			@{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-protect-and-limit-highly-privileged-users' },
			@{ 'Name' = 'Managing user consent for applications using Office 365 APIs'; 'URL' = 'https://learn.microsoft.com/en-us/archive/blogs/exchangedev/managing-user-consent-for-applications-using-office-365-apis' },
			@{ 'Name' = 'Admin Consent for Permissions in Azure Active Directory'; 'URL' = 'https://nicksnettravels.builttoroam.com/post-2017-01-24-admin-consent-for-permissions-in-azure-active-directory-aspx/' })
	}
	return $inspectorobject
}

function Audit-CISAz1130
{
	try
	{
		# Actual Script
		$Policy = Get-MgPolicyAuthorizationPolicy
		
		# Validation
		if ($Policy.DefaultUserRolePermissions.AllowedToCreateApps -eq $true)
		{
			$finalobject = Build-CISAz1130($Policy.DefaultUserRolePermissions.AllowedToCreateApps)
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
return Audit-CISAz1130