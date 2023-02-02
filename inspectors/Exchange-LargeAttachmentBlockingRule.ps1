# This is an LargeAttachmentBlockingRule Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if a LargeAttachmentBlockingRule is existing that blocks large attachments
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-LargeAttachmentBlockingRule($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0039"
		FindingName	     = "No Transport Rules to Block Large Attachment"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "6.5"
		Description	     = "No Exchange Online Transport Rules are in place to block emails with overly large attachments. Emails with overly large attachments may present a security risk for several reasons. Emails the domains receive may have overly large attachments that contain malware, and adversaries sometimes use overly large files in an attempt to bypass anti-malware scanners or otherwise avoid suspicion. An adversary with access to an organizational email account may also use a large attachment to exfiltrate sensitive data from the organization; for example, emailing an encrypted archive file to other adversarial infrastructure using a compromised O365 account. It is often recommended to create a rule that detects and blocks attachments over a certain size for these reasons."
		Remediation	     = "Go to the Exchange Mail Flow rules screen and create a new rule which blocks attachments over a designated size."
		PowerShellScript = 'Get-Mailbox | Set-Mailbox -MaxSendSize 10MB -MaxReceiveSize 10MB; get-transportconfig | Set-TransportConfig -maxsendsize 15MB -maxreceivesize 15MB; get-receiveconnector | set-receiveconnector -maxmessagesize 10MB; get-sendconnector | set-sendconnector -maxmessagesize 10MB; get-mailbox | Set-Mailbox -Maxsendsize 10MB -maxreceivesize 10MB; New-TransportRule -Name LargeAttach -AttachmentSizeOver 10MB -RejectMessageReasonText "Message attachment size over 10MB - email rejected."'
		DefaultValue	 = "No Transport Rule"
		ExpectedValue    = "Configured Transport Rule"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		References	     = @(@{ 'Name' = 'Common Attachment Blocking Scenarios'; 'URL' = "https://docs.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/common-attachment-blocking-scenarios" })
	}
	return $inspectorobject
}

function Inspect-LargeAttachmentBlockingRule
{
	Try
	{
		
		$rules = Get-TransportRule
		$flag = $False
		
		ForEach ($rule in $rules)
		{
			if (($rule.AttachmentSizeOver -like "*") -AND (($rule.DeleteMessage -ne $false) -OR ($null -ne $rule.RejectMessageReasonText)))
			{
				$flag = $True
				# Add the rule to output in future versions eventually!
			}
		}
		
		If (-NOT $flag)
		{
			$endobject = Build-LargeAttachmentBlockingRule($flag)
			return $endobject
		}
		
		return $null
		
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

return Inspect-LargeAttachmentBlockingRule


