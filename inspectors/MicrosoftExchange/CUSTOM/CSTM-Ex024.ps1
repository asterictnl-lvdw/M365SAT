# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks Exchange Mailboxes with Internal Forwarding Rules Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex024($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex024"
		FindingName	     = "CSTM-Ex024 - Mailboxes with Internal Forwarding Rules Enabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "0"
		Description	     = "The Exchange Online mailboxes listed above have Forwarding rules configured enabled. Attackers commonly create hidden forwarding rules in compromised mailboxes. These rules may be exfiltrating data with or without the user's knowledge."
		Remediation	     = "Use the PowerShell Command to disable the Internal Forward Rules based on the EmailAddress. A list is included about which emailadresses are impacted."
		PowerShellScript = 'Remove-InboxRule -Mailbox <email address> -Identity "Rule Name"'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "3"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Office 365 - List all email forwarding rules (PowerShell)'; 'URL' = "https://geekshangout.com/office-365-powershell-list-email-forwarding-rules-mailboxes/" },
			@{ 'Name' = 'Get-Mailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/get-mailbox?view=exchange-ps" })
	}
	return $inspectorobject
}



Function Audit-CSTM-Ex024
{
	Try
	{
		
		$mailboxes = Get-ExoMailbox -ResultSize Unlimited
		
		$knownDomains = (Get-AcceptedDomain).DomainName
		
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
			$endobject = Build-CSTM-Ex024($rulesenabled.MailboxOwnerID | Select-Object -Unique)
			Return $endobject
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}
Audit-CSTM-Ex024


