# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if IMAP is enabled in Mailbox
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex023($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex023"
		FindingName	     = "CSTM-Ex023 - Exchange Mailboxes with IMAP Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "The Exchange Online mailboxes listed above have IMAP Authentication enabled. IMAP Authentication is a method of authenticating to an Exchange Online mailbox. Cyber adversaries have used IMAP authentication as a workaround for subtly conducting password spraying attacks or other credential-related attacks, because IMAP authentication is a form of legacy authentication generally not subject to the restraints of Multi-Factor Authentication and other modern authentication safeguards. For these reasons it is recommended that IMAP Authentication be disabled where possible."
		Remediation	     = "Use the PowerShell Command to disable Mailboxes with IMAP Check with Get-CasMailbox -ResultSize unlimited -Filter PopEnabled -eq `$false -and ImapEnabled -eq `$false"
		PowerShellScript = 'Get-CASMailboxPlan -Filter {ImapEnabled -eq "true" } | set-CASMailboxPlan -ImapEnabled $false; Get-CASMailbox -Filter {ImapEnabled -eq "true"} | Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} | Set-CASMailbox -ImapEnabled $false'
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
function Inspect-CSTM-Ex023
{
	Try
	{
		$Mailboxes = Get-EXOCASMailbox -Filter { ImapEnabled -eq $true } | Select-Object @{ n = "Identity"; e = { $_.primarysmtpaddress } }
		if ($Mailboxes.Count -igt 0)
		{
			$Mailboxes | Out-File -FilePath "$path\ExchangeMailboxeswithIMAPEnabled.txt" -Append
			$endobject = Build-CSTM-Ex023($Mailboxes)
			Return $endobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex023


