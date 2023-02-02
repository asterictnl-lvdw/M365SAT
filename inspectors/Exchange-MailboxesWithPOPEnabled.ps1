# This is an MailboxesWithPOPEnabled Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks Exchange Mailboxes with POP Protocol are Enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-MailboxesWithPOPEnabled($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0046"
		FindingName	     = "Exchange Mailboxes with POP Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "The Exchange Online mailboxes listed have POP enabled. POP is a method of accessing an Exchange Online mailbox. Cyber adversaries have used POP as a workaround for subtly conducting password spraying attacks or other credential-related attacks, because POP is a form of legacy authentication generally not subject to the restraints of Multi-Factor Authentication and other modern authentication safeguards. For these reasons it is recommended that POP be disabled where possible."
		Remediation	     = "This finding refers to individual mailboxes that have POP enabled. For these mailboxes, POP authentication can be disabled using the Set-CASMailbox commandlet. A list of affected email addresses is included in this report. Key stakeholders should be polled prior to making this change, as there is a chance POP is used within the organization for legacy applications or service accounts."
		PowerShellScript = 'Get-CASMailboxPlan -Filter {PopEnabled -eq "true" } | Set-CASMailboxPlan -ImapEnabled $false; Get-CASMailbox -Filter {ImapEnabled -eq "true"} | Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} | Set-CASMailbox -PopEnabled $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Configure mailbox access (POP3 and IMAP)'; 'URL' = "https://docs.microsoft.com/en-us/exchange/clients/pop3-and-imap4/configure-mailbox-access" },
			@{ 'Name' = 'Set-CASMailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps" },
			@{ 'Name' = 'Federal Bureau of Investigation Business Email Compromise Mitigation Recommendations'; 'URL' = "https://www.ic3.gov/Media/Y2020/PSA200406" },
			@{ 'Name' = 'How to disable POP and IMAP for all Mailboxes in Office 365'; 'URL' = "https://gcits.com/knowledge-base/disable-pop-imap-mailboxes-office-365/" })
	}
	return $inspectorobject
}

function Inspect-MailboxesWithPOPEnabled {
	Try
	{
		$Mailboxes = Get-CASMailbox -Filter { PopEnabled -eq "true" } | Select-Object @{ n = "Identity"; e = { $_.primarysmtpaddress } }
		if ($Mailboxes.Count -igt 0)
		{
			$Mailboxes | Out-File -FilePath "$($OutPath)\logs\ExchangeMailboxeswithPOPEnabled.txt" -Append
			$endobject = Build-MailboxesWithPOPEnabled($Mailboxes)
			Return $endobject
		}
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

return Inspect-MailboxesWithPOPEnabled


