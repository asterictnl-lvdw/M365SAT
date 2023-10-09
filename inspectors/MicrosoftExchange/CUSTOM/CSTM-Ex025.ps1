# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Exchange Mailboxes with POP Enabled check
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex025($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex025"
		FindingName	     = "CSTM-Ex025 - Exchange Mailboxes with POP Enabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "The Exchange Online mailboxes listed have POP enabled. POP is a method of accessing an Exchange Online mailbox. Cyber adversaries have used POP as a workaround for subtly conducting password spraying attacks or other credential-related attacks, because POP is a form of legacy authentication generally not subject to the restraints of Multi-Factor Authentication and other modern authentication safeguards. For these reasons it is recommended that POP be disabled where possible."
		Remediation	     = "This finding refers to individual mailboxes that have POP enabled. For these mailboxes, POP authentication can be disabled using the Set-CASMailbox commandlet. A list of affected email addresses is included in this report. Key stakeholders should be polled prior to making this change, as there is a chance POP is used within the organization for legacy applications or service accounts."
		PowerShellScript = 'Get-CASMailboxPlan -Filter {PopEnabled -eq "true" } | Set-CASMailboxPlan -ImapEnabled $false; Get-CASMailbox -Filter {ImapEnabled -eq "true"} | Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} | Set-CASMailbox -PopEnabled $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Configure mailbox access (POP3 and IMAP)'; 'URL' = "https://docs.microsoft.com/en-us/exchange/clients/pop3-and-imap4/configure-mailbox-access" },
			@{ 'Name' = 'Set-CASMailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps" },
			@{ 'Name' = 'Federal Bureau of Investigation Business Email Compromise Mitigation Recommendations'; 'URL' = "https://www.ic3.gov/Media/Y2020/PSA200406" },
			@{ 'Name' = 'How to disable POP and IMAP for all Mailboxes in Office 365'; 'URL' = "https://gcits.com/knowledge-base/disable-pop-imap-mailboxes-office-365/" })
	}
	return $inspectorobject
}

function Inspect-CSTM-Ex025 {
	Try
	{
		$Mailboxes = Get-EXOCASMailbox -Filter { PopEnabled -eq $true } | Select-Object @{ n = "Identity"; e = { $_.primarysmtpaddress } }
		if ($Mailboxes.Count -igt 0)
		{
			$Mailboxes | Out-File -FilePath "$path\ExchangeMailboxeswithPOPEnabled.txt" -Append
			$endobject = Build-CSTM-Ex025($Mailboxes)
			Return $endobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex025


