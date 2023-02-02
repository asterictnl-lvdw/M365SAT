# This is an CheckAdminLicenses Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Office 365
# Purpose: Checks if Admin Accounts Contain Licenses
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-CheckAdminLicenses($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMO3650002"
		FindingName	     = "Microsoft Office Admins contain a license!"
		ProductFamily    = "Microsoft Office 365"
		CVS			     = "9.1"
		Description	     = "Admin accounts should not have licenses for Office applications, due the risk of accessing somebody else's data could have a potential impact on your organisation and so that they have no access to potentially vulnerable services (EX. email, Teams, Sharepoint, etc.) and only access to perform tasks as needed for Administrative purposes."
		Remediation	     = "1. Log in to https://admin.microsoft.com as a Global Administrator. > Azure Active Directory > Users > Active Users > Add a User 2. Fill out the information > 3. When prompted to assign licenses select Create user without product license (not recommended), then click Next > 4. Under the Option settings screen you may choose from several types of Administrative access roles. Choose Admin center access followed by the appropriate role. "
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Add users and assign licenses at the same time'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/add-users?view=o365-worldwide" })
	}
}

function Audit-CheckAdminLicenses
{
	try
	{
		$checkadminlicdata = @()
		$checkadminlic = Get-MsolRole | %{ $role = $_.name; Get-MsolRoleMember -RoleObjectId $_.objectid } | Where-Object -Property isLicensed -match 'True'
		if ($checkadminlic.count -igt 0)
		{
			$checkadminlicdata += "$($checkadminlic.EmailAddress)"
			$endobject = Build-CheckAdminLicenses($checkadminlicdata)
			Return $endobject 
		}
		return $null
	}
	catch
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
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
}
return Audit-CheckAdminLicenses