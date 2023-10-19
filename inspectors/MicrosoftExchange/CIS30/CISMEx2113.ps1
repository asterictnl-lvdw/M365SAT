# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure the spoofed domains report is reviewed weekly
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2113($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx2113"
		FindingName	     = "CIS MEx 2.1.13 - Your Security Threats Status report!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "0"
		Description	     = "While this report isn't strictly actionable, reviewing it will give a sense of the overall volume of various security threats targeting users, which may prompt adoption of more aggressive threat mitigations"
		Remediation	     = "To verify the report is being reviewed at least weekly, confirm that the necessary procedures, by executing the PowerShell script and mapping it to a txt file."
		PowerShellScript = 'Get-BlockedSenderAddress'
		DefaultValue	 = "Undefined"
		ExpectedValue    = "Undefined"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Use DMARC to validate email'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email?view=o365-worldwide" },
			@{ 'Name' = 'DMARC Overview, Anatomy of a DMARC Record, How Senders Deploy DMARC in 5 Steps'; 'URL' = "https://dmarc.org/overview/" },
			@{ 'Name' = 'What is a DMARC record?'; 'URL' = "https://mxtoolbox.com/dmarc/details/what-is-a-dmarc-record" },
			@{ 'Name' = 'DMARC Configuration'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure?view=o365-worldwide" })
	}
}


function Inspect-CISMEx2113
{	
	Try
	{
		$Categories = @('InboundDLPHits','OutboundDLPHits','InboundTransportRuleHits','OutboundTransportRuleHits','InboundDLPPolicyRuleHits','OutboundDLPPolicyRuleHits','TopSpamRecipient','TopMailSender','TopMailRecipient','TopMalwareRecipient','TopMalware')
		#SafeLinks
		Get-SafeLinksAggregateReport | Format-Table -AutoSize | Out-File "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		Get-SafeLinksDetailReport | Format-Table -AutoSize | Out-File -Append "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		#ATP
		Get-MailTrafficATPReport | Format-Table -AutoSize | Out-File -Append  "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		Get-MailDetailATPReport | Format-Table -AutoSize | Out-File -Append "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		#MailTraffic & MailFlow
		foreach ($Category in $Categories)
		{
			Get-MailTrafficSummaryReport -Category $Category | Format-Table -AutoSize | Out-File -Append "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		}
		Get-MailTrafficPolicyReport | Format-Table -AutoSize | Out-File -Append "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		Get-MailFlowStatusReport | Format-Table -AutoSize | Out-File -Append "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		#Content Malware MDO
		Get-ContentMalwareMdoAggregateReport | Format-Table -AutoSize | Out-File -Append "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		Get-ContentMalwareMdoDetailReport | Format-Table -AutoSize | Out-File -Append "$path\CISMEx2113SecurityThreatsStatusReport.txt"
		
		$endobject = Build-CISMEx2113("0")
		Return $endobject
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx2113


