# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Count the Global Administrators
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz117($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz117"
		FindingName	     = "CIS MAz 1.1.7 - Improper Number of Company/Global Administrators"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "12"
		Description	     = "It is recommended that 2 to 4 users be granted company or global administrative privileges. If there is only one global tenant administrator, he or she can perform malicious activity without the possibility of being discovered by another admin. If there are numerous global tenant administrators, the more likely it is that one of their accounts will be successfully breached by an external attacker."
		Remediation	     = "Use the Security and Compliance Center to review the administrative privileges granted to the users listed and determine if each user truly requires their administrative privileges. In many cases a more granular set of permissions may be appropriate. Reduce the privileges of each user as appropriate."
		PowerShellScript = ''
		DefaultValue	 = "1"
		ExpectedValue    = "Between two and four"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "4"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'About Administrative Roles'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide" },
			@{ 'Name' = 'Permissions in the Security and Compliance Center'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/permissions-in-the-security-and-compliance-center?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMAz117
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
			$GlobalAdminList | Format-Table -AutoSize | Out-File "$path\CISMAz113-GlobalAdmins.txt"
			$endobject = Build-CISMAz117($globalAdmins.AdditionalProperties.Count)
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

return Audit-CISMAz117


