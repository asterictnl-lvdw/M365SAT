# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft 365
# Purpose: Ensure that between two and four global admins are designated
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff112($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff113"
		FindingName	     = "CIS MOff 1.1.3 - There are $($findings) global admins designated"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "12"
		Description	     = "If there is only one global tenant administrator, he or she can perform malicious activity without the possibility of being discovered by another admin. If there are numerous global tenant administrators, the more likely it is that one of their accounts will be successfully breached by an external attacker."
		Remediation	     = "Create an extra Global Admin Account if you only have one or remove Global Admin permissions from accounts if you have more than four."
		PowerShellScript = 'https://admin.microsoft.com/'
		DefaultValue	 = "1"
		ExpectedValue    = "Between 2 and 4"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage emergency access accounts in Microsoft Entra ID'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access" },
			@{ 'Name' = 'Securing privileged access for hybrid and cloud deployments in Microsoft Entra ID'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning#stage-1-critical-items-to-do-right-now" })
	}
	return $inspectorobject
}

function Audit-CISMOff112
{
	Try
	{
		#Original Script
		#$globalAdminRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'"
		#$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId 
		#$globalAdminRole.Id

		# Custom Script
		$global_admins = (Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").id | ForEach-Object { Get-MgDirectoryObjectById -Ids $_.id }).AdditionalProperties.userPrincipalName
		$num_global_admins = ($global_admins | Measure-Object).Count
		
		If ($num_global_admins -lt 2 -or $num_global_admins -igt 4)
		{
			$global_admins | Format-Table -AutoSize | Out-File "$path\CISMOff113-GlobalAdmins.txt"
			$endobject = Build-CISMOff112($num_global_admins)
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

return Audit-CISMOff112


