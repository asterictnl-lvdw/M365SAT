# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Users can create security groups in Azure portals, API or PowerShell' is set to 'No'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1180($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1180"
		FindingName	     = "CIS Az 1.18 - Users can create security groups in Azure portals, API or PowerShell"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "When creating security groups is enabled, all users in the directory are allowed to create new security groups and add members to those groups. Unless a business requires this day-to-day delegation, security group creation should be restricted to administrators only."
		Remediation	     = "Use the Powershell Script to modify the policy to disallow Tenant Creation by unauthorized users"
		PowerShellScript = '$RolePermissions = @{}; $RolePermissions["AllowedToCreateSecurityGroups"] = $False; Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -DefaultUserRolePermissions $RolePermissions'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Set up self-service group management in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management#making-a-group-available-for-end-user-self-service' },
			@{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' },
			@{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategyment'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
			@{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' })
	}
return $inspectorobject
}

function Audit-CISAz1180
{
	try
	{
		$AuthorizationSettings = Get-MgPolicyAuthorizationPolicy
		if ($AuthorizationSettings.DefaultUserRolePermissions.AllowedToCreateSecurityGroups -eq $true)
		{
			$finalobject = Build-CISAz1180("AllowedToCreateSecurityGroups: $($AuthorizationSettings.DefaultUserRolePermissions.AllowedToCreateSecurityGroups)")
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
return Audit-CISAz1180