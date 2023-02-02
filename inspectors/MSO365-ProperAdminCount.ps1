# This is an ProperAdminCount Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Office 365
# Purpose: Checks if there are a correct amount of Admins existing within the Office 365 tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-ProperAdminCount($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMO3650001"
		FindingName	     = "Improper Number of Company/Global Administrators"
		ProductFamily    = "Microsoft Office 365"
		CVS			     = "8.3"
		Description	     = "It is recommended that 2 to 4 users be granted company or global administrative privileges. More than this amount may represent an unsafe distribution of privileges and increases the odds that an administrative account will be compromised by an adversary or otherwise misused. All of the users above have administrative privileges, which is outside the bounds of the recommendation."
		Remediation	     = "Use the Security and Compliance Center to review the administrative privileges granted to the users listed and determine if each user truly requires their administrative privileges. In many cases a more granular set of permissions may be appropriate. Reduce the privileges of each user as appropriate."
		PowerShellScript = ''
		DefaultValue	 = "1"
		ExpectedValue    = "Between two and four"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'About Administrative Roles'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide" },
			@{ 'Name' = 'Permissions in the Security and Compliance Center'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/permissions-in-the-security-and-compliance-center?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Inspect-ProperAdminCount
{
	Try
	{
		
		$global_admins = (Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").id | ForEach-Object { Get-AzureADObjectByObjectId -ObjectIds $_.id }).DisplayName
		$num_global_admins = ($global_admins | Measure-Object).Count
		
		If (($num_global_admins -lt 2) -or ($num_global_admins -gt 4))
		{
			$endobject = Build-ProperAdminCount($global_admins)
			Return $endobject
		}
		
		return $null
		
	}
	Catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname -failinglinenumber $failinglinenumber -failingline $failingline -pscommandpath $pscommandpath -positionmsg $pscommandpath -stacktrace $strace
		Write-Verbose "Errors written to log"
	}
	
}

return Inspect-ProperAdminCount


