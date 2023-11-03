# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft 365
# Purpose: Ensure two emergency access accounts have been defined
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff112($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff112"
		FindingName	     = "CIS MOff 1.1.2 - Ensure two emergency access accounts have been defined"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "12"
		Description	     = "In various situations, an organization may require the use of a break glass account to gain emergency access. In the event of losing access to administrative functions, an organization may experience a significant loss in its ability to provide support, lose insight into its security posture, and potentially suffer financial losses."
		Remediation	     = "Create an extra Global Admin Account if you only have one. "
		PowerShellScript = '-'
		DefaultValue	 = "1"
		ExpectedValue    = "2"
		ReturnedValue    = $findings.Count
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'About Administrative Roles'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide" },
			@{ 'Name' = 'Permissions in the Security and Compliance Center'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/permissions-in-the-security-and-compliance-center?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMOff112
{
	Try
	{
		
		$global_admins = (Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").id | ForEach-Object { Get-MgDirectoryObjectById -Ids $_.id }).AdditionalProperties.userPrincipalName
		$num_global_admins = ($global_admins | Measure-Object).Count
		
		If ($num_global_admins -ne 2)
		{
			$global_admins | Format-Table -AutoSize | Out-File "$path\CISMOff112EmergencyAccounts.txt"
			$endobject = Build-CISMOff112($global_admins)
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


