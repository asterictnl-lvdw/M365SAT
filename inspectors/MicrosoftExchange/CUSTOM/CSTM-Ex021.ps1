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

function Build-CSTM-Ex021($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex021"
		FindingName	     = "CSTM-Ex021 - No Transport Rules to Block Large Attachment"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "No Exchange Online Transport Rules are in place to block emails with overly large attachments. Emails with overly large attachments may present a security risk for several reasons. Emails the domains receive may have overly large attachments that contain malware, and adversaries sometimes use overly large files in an attempt to bypass anti-malware scanners or otherwise avoid suspicion. An adversary with access to an organizational email account may also use a large attachment to exfiltrate sensitive data from the organization; for example, emailing an encrypted archive file to other adversarial infrastructure using a compromised O365 account. It is often recommended to create a rule that detects and blocks attachments over a certain size for these reasons."
		Remediation	     = "Go to the Exchange Mail Flow rules screen and create a new rule which blocks attachments over a designated size."
		PowerShellScript = 'Get-Mailbox | Set-Mailbox -MaxSendSize 10MB -MaxReceiveSize 10MB; get-transportconfig | Set-TransportConfig -maxsendsize 15MB -maxreceivesize 15MB; get-receiveconnector | set-receiveconnector -maxmessagesize 10MB; get-sendconnector | set-sendconnector -maxmessagesize 10MB; get-mailbox | Set-Mailbox -Maxsendsize 10MB -maxreceivesize 10MB; New-TransportRule -Name LargeAttach -AttachmentSizeOver 10MB -RejectMessageReasonText "Message attachment size over 10MB - email rejected."'
		DefaultValue	 = "No Transport Rule"
		ExpectedValue    = "Configured Transport Rule"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Common Attachment Blocking Scenarios'; 'URL' = "https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/common-attachment-blocking-scenarios" })
	}
	return $inspectorobject
}

function Inspect-CSTM-Ex021
{
	Try
	{
		
		$rules = Get-TransportRule | Where-Object {($_.AttachmentSizeOver -like "*") -and ($_.DeleteMessage -ne $false -or $_.RejectMessageReasonText -ne $null)}
		if (-not [string]::IsNullOrEmpty($rules))
		{
			ForEach ($rule in $rules)
			{
				#Needs to be properly validated here...
			}
			$endobject = Build-CSTM-Ex021($rules)
			return $endobject
		}
		else
		{
			return $null
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex021


