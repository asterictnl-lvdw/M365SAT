# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: IP Addresses Spam checker
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex026($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex026"
		FindingName	     = "CSTM-Ex026 - Exchange Mailboxes with SMTP Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "The Exchange Online mailboxes listed have SMTP Authentication enabled. SMTP Authentication is a method of authenticating to an Exchange Online mailbox. Cyber adversaries have used SMTP authentication as a workaround for subtly conducting password spraying attacks or other credential-related attacks, because SMTP authentication is a form of legacy authentication generally not subject to the restraints of Multi-Factor Authentication and other modern authentication safeguards. For these reasons it is recommended that SMTP Authentication be disabled where possible."
		Remediation	     = "This finding refers to individual mailboxes that have SMTP enabled. For these mailboxes, SMTP authentication can be disabled using the Set-CASMailbox commandlet. A list of affected email addresses is included in this report. Key stakeholders should be polled prior to making this change, as there is a chance SMTP is used within the organization for legacy applications or service accounts."
		PowerShellScript = '1. Get-CASMailboxPlan -Filter {SmtpClientAuthenticationDisabled -eq "false" } | Set-CASMailboxPlan -SmtpClientAuthenticationDisabled $true 2. Get-CASMailbox -Filter {SmtpClientAuthenticationDisabled -eq "true"} | Select-Object @{n = "Identity"; e = {$_.primarysmtpaddress}} | Set-CASMailbox -SmtpClientAuthenticationDisabled $true'
		DefaultValue	 = "True or Null"
		ExpectedValue    = "False and No Mailboxes"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Enable or disable authenticated client SMTP submission (SMTP AUTH) in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/authenticated-client-smtp-submission" },
			@{ 'Name' = 'Set-CASMailbox Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-casmailbox?view=exchange-ps" },
			@{ 'Name' = 'Federal Bureau of Investigation Business Email Compromise Mitigation Recommendations'; 'URL' = "https://www.ic3.gov/Media/Y2020/PSA200406" },
			@{ 'Name' = 'How to disable POP and IMAP for all Mailboxes in Office 365'; 'URL' = "https://gcits.com/knowledge-base/disable-pop-imap-mailboxes-office-365/" })
	}
	return $inspectorobject
}


function Inspect-CSTM-Ex026
{
	Try
	{
		$Users = Get-EXOCASMailbox -ResultSize unlimited -Properties SmtpClientAuthenticationDisabled
		$Mailboxes = ($Users | where { $_.SmtpClientAuthenticationDisabled -eq $true })
		$Validation = Get-TransportConfig | Select-Object SmtpClientAuthenticationDisabled
		if ($Validation.SmtpClientAuthenticationDisabled -eq $True -or $Mailboxes.Count -ne 0)
		{
			$Mailboxes | Out-File -FilePath "$($path)\ExchangeMailboxeswithPOPEnabled.txt" -Append
			$Validation | Out-File -FilePath "$($path)\ExchangeMailboxeswithPOPEnabled.txt" -Append
			$endobject = Build-CSTM-Ex026($Mailboxes)
			Return $endobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex026


