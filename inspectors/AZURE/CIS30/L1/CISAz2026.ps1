# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure fewer than 5 users have global administrator assignment
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz2026($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2026"
		FindingName	     = "CIS Az 2.26 - There are less than 1 or more than 5 users with an global administrator assignment"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "12"
		Description	     = "The Global Administrator role has extensive privileges across all services in Microsoft Entra ID. The Global Administrator role should never be used in regular daily activities; administrators should have a regular user account for daily activities, and a separate account for administrative responsibilities. Limiting the number of Global Administrators helps mitigate the risk of unauthorized access, reduces the potential impact of human error, and aligns with the principle of least privilege to reduce the attack surface of an Azure tenant. Conversely, having at least two Global Administrators ensures that administrative functions can be performed without interruption in case of unavailability of a single admin."
		Remediation	     = "Use the Security and Compliance Center to review the administrative privileges granted to the users listed and determine if each user truly requires their administrative privileges. In many cases a more granular set of permissions may be appropriate. Reduce the privileges of each user as appropriate."
		PowerShellScript = ''
		DefaultValue	 = "1"
		ExpectedValue    = "Between two and four"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "4"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Limit the number of Global Administrators to less than 5'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#5-limit-the-number-of-global-administrators-to-less-than-5" },
			@{ 'Name' = 'Security guidelines for assigning roles'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide#security-guidelines-for-assigning-roles" },
			@{ 'Name' = 'Manage emergency access accounts in Microsoft Entra ID'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access" },
			@{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' })
	}
	return $inspectorobject
}

function Audit-CISAz2026
{
	Try
	{
		
		$GlobalAdminList = @()
		# Determine Id of role using the immutable RoleTemplateId value. 		
		$globalAdminRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'" 
		$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
		
		foreach ($GlobalAdmin in $globalAdmins)
		{
			$GlobalAdminList += $globalAdmin.AdditionalProperties.displayName
		}
		
		If (($globalAdmins.AdditionalProperties.Count -lt 2) -or ($globalAdmins.AdditionalProperties.Count -gt 4))
		{
			$GlobalAdminList | Format-Table -AutoSize | Out-File "$path\CISAz2026-GlobalAdmins.txt"
			$endobject = Build-CISAz2026($globalAdmins.AdditionalProperties.Count)
			Return $endobject
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}

return Audit-CISAz2026


