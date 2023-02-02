# This is an DirSyncSvcAcct Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Directory Synchronization Service Account is existing
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-DirSyncSvcAcct($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0008"
		FindingName	     = "Directory Synchronization Service Account Found"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "0.0"
		Description	     = "Directory synchronization allows you to manage identities in your Active Directory Domain Services (AD DS) and all updates to user accounts, groups, and contacts are synchronized to the Azure Active Directory (Azure AD) tenant of your Microsoft 365 subscription."
		Remediation	     = "Validate the Configuration of the Service Account to determine if default installation procedure is used. If so, please use Microsoft's guidace to apply best practices."
		PowerShellScript = ''
		DefaultValue	 = "-"
		ExpectedValue    = "-"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'ADSync Service accounts'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/hybrid/concept-adsync-service-account" },
			@{ 'Name' = 'Service accounts'; 'URL' = "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts" },
			@{ 'Name' = 'Virtual accounts'; 'URL' = "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/service-accounts#bkmk-virtualserviceaccounts" })
	}
}



Function Get-DirSyncSvcAcct
{
	Try
	{
		
		$permissions = Get-MgOrganization
		
		If ($permissions.OnPremisesSyncEnabled -eq $true)
		{
			$directoryRole = Get-MgDirectoryRole | Where-Object { $_.DisplayName -eq "Directory Synchronization Accounts" }
			$roleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $directoryRole.Id
			$serviceAcct = Get-MgUser -UserId ($roleMembers).Id
			$endobject = Build-DirSyncSvcAcct($serviceAcct.DisplayName)
			Return $endobject
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

Return Get-DirSyncSvcAcct




