# This is an ExchangeSpamFilterPolicy Inspector.

# Date 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Exchange has a SpamFilterPolicy Active
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-ExchangeSpamFilterPolicy($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0062"
		FindingName	     = "Spam Policy Setting on Exchange Online Not Existing or Not Correctly Configured!"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "3.3"
		Description	     = "You should set your Exchange Online Spam Policies to copy emails and notify someone when a sender in your tenant has been blocked for sending spam emails."
		Remediation	     = "Use the PowerShell to modify the settings of the SpamFilterPolicy"
		PowerShellScript = 'Set-HostedContentFilterPolicy -Identity "Default" -SpamAction MoveToJmf -BulkSpamAction MoveToJmf -HighConfidenceSpamAction MoveToJmf -BulkThreshold 5 -IncreaseScoreWithBizOrInfoUrls On -IncreaseScoreWithImageLinks On -IncreaseScoreWithNumericIps On -IncreaseScoreWithRedirectToOtherPort On -MarkAsSpamBulkMail On -MarkAsSpamEmbedTagsInHtml On -MarkAsSpamEmptyMessages On -MarkAsSpamFormTagsInHtml On -MarkAsSpamFramesInHtml On -MarkAsSpamFromAddressAuthFail On -MarkAsSpamJavaScriptInHtml On -MarkAsSpamNdrBackscatter On -MarkAsSpamObjectTagsInHtml On -MarkAsSpamSpfRecordHardFail On -MarkAsSpamWebBugsInHtml On -MarkAsSpamSensitiveWordList On -TestModeAction AddXHeader'
		DefaultValue	 = "BccSuspiciousOutboundMail: False <br /> NotifyOutboundSpamRecipients: Null <br /> NotifyOutboundSpam: False"
		ExpectedValue    = "BccSuspiciousOutboundMail: True <br /> NotifyOutboundSpamRecipients: example@mail.org <br /> NotifyOutboundSpam: True"
		ReturnedValue    = $findings
		Impact		     = "Low"
		RiskRating	     = "Low"
		References	     = @(@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = "9.7 Deploy and Maintain Email Server Anti-Malware Protections" },
			@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = "10.5 Enable Anti-Exploitation Features" },
			@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = "7.9 Block Unnecessary File Types" })
	}
	return $inspectorobject
}

function Audit-ExchangeSpamFilterPolicy
{
	try
	{
		$ExchangeSpamFilterPolicyData = @()
		$ExchangeSpamFilterPolicy = Get-HostedOutboundSpamFilterPolicy | Select-Object BccSuspiciousOutboundMail, NotifyOutboundSpamRecipients, NotifyOutboundSpam
		if ($ExchangeSpamFilterPolicy.BccSuspiciousOutboundMail -match 'False' -or $audit.NotifyOutboundSpamRecipients -eq $null -or $ExchangeSpamFilterPolicy.NotifyOutboundSpam -match 'False')
		{
			$ExchangeSpamFilterPolicyData += " BccSuspiciousOutboundMail: " + $ExchangeSpamFilterPolicy.BccSuspiciousOutboundMail
			$ExchangeSpamFilterPolicyData += "`n NotifyOutboundSpamRecipients: " + $ExchangeSpamFilterPolicy.NotifyOutboundSpamRecipients
			$ExchangeSpamFilterPolicyData += "`n NotifyOutboundSpam: " + $ExchangeSpamFilterPolicy.NotifyOutboundSpam
			$endobject = Build-ExchangeSpamFilterPolicy($ExchangeSpamFilterPolicyData)
			Return $endobject
		}
		return $null
	}
	catch
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
return Audit-ExchangeSpamFilterPolicy