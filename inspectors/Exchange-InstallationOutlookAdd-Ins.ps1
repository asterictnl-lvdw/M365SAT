# This is an InstallationOutlookAdd-Ins Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if OutlookAdd-Ins can be installed by normal users
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-InstallationOutlookAddIns($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0036"
		FindingName	     = "Users can Install Outlook Add-ins"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "Attackers commonly use vulnerable and custom-built add-ins to access data in user applications. While allowing users to install add-ins by themselves does allow them to easily acquire useful add-ins that integrate with Microsoft applications, it can represent a risk if not used and monitored carefully."
		Remediation	     = "Use the Tenable Reference and use the PowerShell template within the article."
		PowerShellScript = 'New-RoleAssignmentPolicy -Name "Example" -Roles $revisedRoles'
		DefaultValue	 = "Users can Install Outlook Add-Ins"
		ExpectedValue    = "Users cannot Install Outlook Add-Ins"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = '2.8 - Ensure users installing Outlook add-ins is not allowed'; 'URL' = "https://www.tenable.com/audits/items/CIS_Microsoft_365_v1.5.0_E3_Level_2.audit:51eaf859366d9e68cf92204846b01329" })
	}
	return $inspectorobject
}

function Audit-InstallationOutlookAddIns
{
	try
	{
		$InstallationOutlookAddInsData = @()
		$InstallationOutlookAddIns = Get-EXOMailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Where-Object { $_.AssignedRoles -like "*Apps*" } } | Select-Object Identity, @{ Name = "AssignedRoles"; Expression = { Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Select-Object -ExpandProperty AssignedRoles | Where-Object { $_ -like "*Apps*" } } } }
		if ($InstallationOutlookAddIns.AssignedRoles -contains 'My Marketplace Apps' -or 'My Custom Apps' -or 'My ReadWriteMailbox Apps')
		{
			foreach ($InstallationOutlookAddInsDataObj in $InstallationOutlookAddIns)
			{
				$InstallationOutlookAddInsData += "$($InstallationOutlookAddIns.Identity), $($InstallationOutlookAddIns.AssignedRoles)"
			}
			$endobject = Build-InstallationOutlookAddIns($InstallationOutlookAddInsData)
			return $endobject
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
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
}
return Audit-InstallationOutlookAddIns