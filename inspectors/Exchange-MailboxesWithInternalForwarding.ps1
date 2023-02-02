# This is an InternalMailboxForwarding Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks Exchange Mailboxes with Internal Forwarding Rules Enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-InternalMailboxForwarding($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0045"
		FindingName	     = "Exchange MailboxPlans with IMAP Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "5.7"
		Description	     = "The Exchange Online mailboxes listed above have Forwarding rules configured enabled. Attackers commonly create hidden forwarding rules in compromised mailboxes. These rules may be exfiltrating data with or without the user's knowledge."
		Remediation	     = "Use the PowerShell Command to disable the Internal Forward Rules based on the EmailAddress. A list is included about which emailadresses are impacted."
		PowerShellScript = 'Remove-InboxRule -Mailbox <email address> -Identity "Rule Name"'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		References	     = @(@{ 'Name' = 'Office 365 - List all email forwarding rules (PowerShell)'; 'URL' = "https://geekshangout.com/office-365-powershell-list-email-forwarding-rules-mailboxes/" },
			@{ 'Name' = 'Get-Mailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/get-mailbox?view=exchange-ps" })
	}
	return $inspectorobject
}



Function Get-InternalMailboxForwarding
{
	Try
	{
		
		$mailboxes = Get-Mailbox -ResultSize Unlimited
		
		$knownDomains = (Get-MgDomain).Id
		
		$rulesEnabled = @()
		
		foreach ($mailbox in $mailboxes)
		{
			$rulesEnabled += Get-InboxRule -Mailbox $mailbox.UserPrincipalName | Where-Object { ($null -ne $_.ForwardTo) -or ($null -ne $_.ForwardAsAttachmentTo) -or ($null -ne $_.RedirectTo) } | Select-Object MailboxOwnerId, RuleIdentity, Name, ForwardTo, RedirectTo
		}
		if ($rulesEnabled.Count -gt 0)
		{
			foreach ($domain in $knownDomains)
			{
				$rulesEnabled | Where-Object { ($_.ForwardTo -match "EX:/o=") -or ($_.ForwardAsAttachmentTo -match "EX:/o=") -or ($_.RedirectTo -match "EX:/o=") } | Out-File -FilePath "$($path)\ExchangeMailboxeswithInternalForwardingRules.txt" -Append
				
				
			}
			$endobject = Build-InternalMailboxForwarding($rulesenabled.MailboxOwnerID | Select-Object -Unique)
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

Get-InternalMailboxForwarding


