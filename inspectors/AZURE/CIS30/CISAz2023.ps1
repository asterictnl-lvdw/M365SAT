# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That No Custom Subscription Administrator Roles Exist
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2023($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2023"
		FindingName	     = "CIS Az 2.23 - Custom Subscription Administrator Roles Exist"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Classic subscription admin roles offer basic access management and include Account Administrator, Service Administrator, and Co-Administrators. It is recommended the least necessary permissions be given initially. Permissions can be added as needed by the account holder. This ensures the account holder cannot perform actions which were not intended."
		Remediation	     = "Use the Azure CloudShell Script to enable Security Defaults on Microsoft Azure Active Directory"
		PowerShellScript = 'az role definition delete --name <role name>'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Add or change Azure subscription administrators'; 'URL' = 'https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/add-change-subscription-administrator' },
		@{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' },
		@{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
		@{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategyment'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
		@{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' },
		@{ 'Name' = 'PA-7: Follow just enough administration (least privilege) principle'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-privileged-access#pa-7-follow-just-enough-administration-least-privilege-principle' })
	}
	return $inspectorobject
}

function Audit-CISAz2023
{
	try
	{
		$CustomSubscriptionAdministratorRoleList = @()
		# Actual Script
		$CustomSubscriptionAdministratorRoles = Get-AzRoleDefinition | Where-Object { ($_.IsCustom -eq $true) -and ($_.Actions.contains('*')) }
		
		if ($CustomSubscriptionAdministratorRoles.Count -igt 0)
		{
			foreach ($Role in $CustomSubscriptionAdministratorRoles)
			{
				$CustomSubscriptionAdministratorRoleList += $Role.Name
			}
			$finalobject = Build-CISAz2023($CustomSubscriptionAdministratorRoleList)
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
return Audit-CISAz2023