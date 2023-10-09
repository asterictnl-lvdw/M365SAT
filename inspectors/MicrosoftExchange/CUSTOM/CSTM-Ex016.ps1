# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Exchange Mailbox Forwarding Rules to External Recipients
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex016($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex016"
		FindingName	     = "CSTM-Ex016 - Exchange Mailboxes with Forwarding Rules to External Recipients"
		ProductFamily    = "Microsoft Exchange"
		RiskScore		     = "12"
		Description	     = "Email forwarding can be useful but can also pose a security risk due to the potential disclosure of information. Attackers might use this information to attack your organization or partners. The mailboxes returned in this finding all forward mail to external recipients."
		Remediation	     = "This finding refers to individual mailboxes that have forwarding rules enabled to external recipients. For these mailboxes, verify that the forwarding rules do not violate company policy, are expected, and allowed. Remediation can be accomplished by running the PowerShell command. A list of affected email addresses is included in this report. You can use the references as well to remediate this issue"
		PowerShellScript = 'Get-Mailbox -ResultSize Unlimited | Where {($_.ForwardingAddress -ne $Null) -or ($_.ForwardingsmtpAddress -ne $Null)} | Set-Mailbox -ForwardingAddress $null -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false; Get-RemoteDomain | Set-RemoteDomain -AutoForwardEnabled $false'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Office 365 - List all email forwarding rules (PowerShell)'; 'URL' = "https://geekshangout.com/office-365-powershell-list-email-forwarding-rules-mailboxes/" },
			@{ 'Name' = 'Get-Mailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/get-mailbox?view=exchange-ps" },
			@{ 'Name' = 'Remove forwarding from Office 365 Mailboxes with Powershell'; 'URL' = "https://www.tachytelic.net/2019/06/remove-forwarding-office-365-powershell/" },
			@{ 'Name' = 'DISABLE FORWARDING IN OWA WITH POWERSHELL'; 'URL' = "https://mehic.se/2019/08/08/disable-forwarding-in-owa-with-powershell/" })
	}
	return $inspectorobject
}

Function Inspect-CSTM-Ex016
{
	Try
	{
		
		$mailboxes = Get-ExoMailbox -ResultSize Unlimited -Properties ForwardingSmtpAddress, DeliverToMailboxAndForward | Where-Object { ($_.ForwardingSmtpAddress -ne $Null) -or ($_.DeliverToMailboxAndForward -ne $False) }
		
		$knownDomains = (Get-AcceptedDomain).DomainName
		
		$rulesEnabled = @()
		
		if ($mailboxes.count -igt 0)
		{
			foreach ($mailbox in $mailboxes)
			{
				$rulesEnabled += Get-InboxRule -Mailbox $mailbox.UserPrincipalName | Where-Object { ($null -ne $_.ForwardTo) -or ($null -ne $_.ForwardAsAttachmentTo) -or ($null -ne $_.RedirectTo) } | Select-Object MailboxOwnerId, RuleIdentity, Name, ForwardTo, RedirectTo, ForwardAsAttachmentTo
			}
		}
		if ($rulesEnabled.Count -gt 0)
		{
			foreach ($domain in $knownDomains)
			{
				$rulesEnabled | Where-Object { (($_.ForwardTo -notmatch "$domain") -or ($_.ForwardAsAttachmentTo -notmatch "$domain") -or ($_.RedirectTo -notmatch "$domain")) -and (($_.ForwardTo -notmatch "EX:/o") -and ($_.ForwardAsAttachmentTo -notmatch "EX:/o") -and ($_.RedirectTo -notmatch "EX:/o")) } | Out-File -FilePath "$($path)\ExchangeMailboxeswithExternalForwardingRules.txt" -Append
			}
			$endobject = Build-CSTM-Ex016($rulesEnabled.Count)
			return $endobject
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

Inspect-CSTM-Ex016


