# This is an eDiscoveryAdmins Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if eDiscoveryAdmins are active in your tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-eDiscoveryAdmins($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0027"
		FindingName	     = "Risky eDiscovery Case Administrators"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "6.5"
		Description	     = "Microsoft Compliance Center eDiscovery provides a method for organizations to search and export content from Microsoft 365 and Office 365. eDiscovery searches are able to access all sources of information, including users' mailboxes to return the requested content. By default, no users are assigned the eDiscovery Administrator role and users may only access cases and searches that they have created."
		Remediation	     = "Review the list of users who are assigned this role, determine if these assignments are appropriate for the tenant and remove any users who should not hold this role."
		PowerShellScript = 'Remove-eDiscoveryCaseAdmin -User example@contoso.com'
		DefaultValue	 = "No eDiscovery Admins"
		ExpectedValue    = "No eDiscovery Admins / Approved Users"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		References	     = @(@{ 'Name' = 'Get started with Core eDiscovery in Microsoft 365'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/get-started-core-ediscovery?view=o365-worldwide" },
			@{ 'Name' = 'More information about the eDiscovery Manager role group'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/get-started-core-ediscovery?view=o365-worldwide#more-information-about-the-ediscovery-manager-role-group" })
	}
	return $inspectorobject
}


Function Inspect-eDiscoveryAdmins
{
	Try
	{
		
		$eDiscoveryAdmins = Get-eDiscoveryCaseAdmin
		
		if ($eDiscoveryAdmins -ne $null)
		{
			$endobject = Build-eDiscoveryAdmins($eDiscoveryAdmins.Name)
			return $endobject
		}
		Return $null
		
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
return Inspect-eDiscoveryAdmins


