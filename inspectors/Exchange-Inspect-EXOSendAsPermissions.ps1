# This is an EXOSendAsPermissions Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks which users have sendas permissions on mailboxes
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Define Output for file
$path = @($OutPath)

function Build-EXOSendAsPermissions($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0029"
		FindingName	     = "Exchange Mailboxes with SendAs Delegates Found"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "The Exchange Online mailboxes listed above have delegated SendAs Access permissions to another account."
		Remediation	     = "This finding refers to individual mailboxes that have SendAs Access delegated permissions. For these mailboxes, verify that the delegate access is expected, appropriate, and do not violate company policy."
		PowerShellScript = 'Remove-MailboxPermission -Identity mailbox -AccessRights SendAs -Confirm:$false -User user'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.ToString()
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Remove-MailboxPermission Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/remove-mailboxpermission?view=exchange-ps" })
	}
	return $inspectorobject
}

Function Inspect-EXOSendAsPermissions
{
	Try
	{
		
		
		$sendAs = Get-Mailbox -ResultSize Unlimited | Get-RecipientPermission | Where-Object { ($_.Trustee -ne 'NT AUTHORITY\SELF') -and ($_.AccessControlType -eq "Allow") -and ($_.AccessRights -eq 'SendAs') }
		
		if ($sendAs.Count -gt 0)
		{
			$sendAs | Out-File -FilePath "$($path)\EXOSendAsPermissions.txt" -Append
			$endobject = Build-EXOSendAsPermissions($sendAs.Count)
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

Inspect-EXOSendAsPermissions


