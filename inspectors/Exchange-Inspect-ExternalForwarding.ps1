# This is an ExternalForwarding Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks which users have external forwarding rules activated within their mailbox
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Define Output for file
$path = @($OutPath)

function Build-ExternalForwarding($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0031"
		FindingName	     = "Exchange Mailboxes with Forwarding Rules to External Recipients"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "Email forwarding can be useful but can also pose a security risk due to the potential disclosure of information. Attackers might use this information to attack your organization or partners. The mailboxes returned in this finding all forward mail to external recipients."
		Remediation	     = "This finding refers to individual mailboxes that have forwarding rules enabled to external recipients. For these mailboxes, verify that the forwarding rules do not violate company policy, are expected, and allowed. Remediation can be accomplished by running the PowerShell command. A list of affected email addresses is included in this report. You can use the references as well to remediate this issue"
		PowerShellScript = 'Get-Mailbox -ResultSize Unlimited | Where {($_.ForwardingAddress -ne $Null) -or ($_.ForwardingsmtpAddress -ne $Null)} | Set-Mailbox -ForwardingAddress $null -ForwardingSmtpAddress $null; Get-RemoteDomain | Set-RemoteDomain -AutoForwardEnabled $false'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.ToString()
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Office 365 - List all email forwarding rules (PowerShell)'; 'URL' = "https://geekshangout.com/office-365-powershell-list-email-forwarding-rules-mailboxes/" },
			@{ 'Name' = 'Get-Mailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/get-mailbox?view=exchange-ps" },
			@{ 'Name' = 'Remove forwarding from Office 365 Mailboxes with Powershell'; 'URL' = "https://www.tachytelic.net/2019/06/remove-forwarding-office-365-powershell/" },
			@{ 'Name' = 'DISABLE FORWARDING IN OWA WITH POWERSHELL'; 'URL' = "https://mehic.se/2019/08/08/disable-forwarding-in-owa-with-powershell/" })
	}    return $inspectorobject
}

Function Inspect-ExternalForwarding
{
	Try
	{
		
		$mailboxes = Get-Mailbox -ResultSize Unlimited | Where { ($_.ForwardingAddress -ne $Null) -or ($_.ForwardingsmtpAddress -ne $Null) }
		
		$knownDomains = (Get-MgDomain).Id
		
		$rulesEnabled = @()
		
		foreach ($mailbox in $mailboxes)
		{
			$rulesEnabled += Get-InboxRule -Mailbox $mailbox.UserPrincipalName | Where-Object { ($null -ne $_.ForwardTo) -or ($null -ne $_.ForwardAsAttachmentTo) -or ($null -ne $_.RedirectTo) } | Select-Object MailboxOwnerId, RuleIdentity, Name, ForwardTo, RedirectTo, ForwardAsAttachmentTo
		}
		if ($rulesEnabled.Count -gt 0)
		{
			foreach ($domain in $knownDomains)
			{
				$rulesEnabled | Where-Object { (($_.ForwardTo -notmatch "$domain") -or ($_.ForwardAsAttachmentTo -notmatch "$domain") -or ($_.RedirectTo -notmatch "$domain")) -and (($_.ForwardTo -notmatch "EX:/o") -and ($_.ForwardAsAttachmentTo -notmatch "EX:/o") -and ($_.RedirectTo -notmatch "EX:/o")) } | Out-File -FilePath "$($path)\ExchangeMailboxeswithExternalForwardingRules.txt" -Append
				$endobject = Build-ExternalForwarding($rulesEnabled.Count)
				return $endobject
			}
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

Inspect-ExternalForwarding


