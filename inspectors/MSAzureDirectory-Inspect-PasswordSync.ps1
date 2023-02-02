# This is an PasswordSync Inspector.

# Date: 22-11-2022
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Password Hash Sync is enabled within the tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-PasswordSync($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0014"
		FindingName	     = "Password Synchronization Enabled"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "0.0"
		Description	     = "Password hash synchronization is one of the sign-in methods used to accomplish hybrid identity. Azure AD Connect synchronizes a hash, of the hash, of a user's password from an on-premises Active Directory instance to a cloud-based Azure AD instance."
		Remediation	     = "Follow Microsoft guidance and best practices to ensure your hybrid configuration meets your business needs and policies."
		PowerShellScript = 'Please use the StackOverflow Solution to disable Password Synchronization'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'What is password hash synchronization with Azure AD?'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-phs" },
			@{ 'Name' = 'Is there any ps command to disable password hash sync?'; 'URL' = "https://stackoverflow.com/questions/62036670/is-there-any-ps-command-to-disable-password-hash-sync" })
	}
}

Function Inspect-PasswordSync
{
	Try
	{
		
		$syncTime = (Invoke-MSGraphRequest -Url 'https://graph.microsoft.com/beta/organization' -HttpMethod GET).Value.onPremisesLastPasswordSyncDateTime
		
		If ($null -ne $syncTime)
		{
			$endobject = Build-PasswordSync("Password Synchronization is enabled. Last synced $syncTime")
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

Return Inspect-PasswordSync


