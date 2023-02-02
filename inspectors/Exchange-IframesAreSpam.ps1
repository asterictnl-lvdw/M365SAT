# This is an IframesAreSpam Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if iFrames are marked as Spam
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-IframesAreSpam($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0024"
		FindingName	     = "iFrames Not Identified as Spam"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "Cyber adversaries often place HTML iframes in the body of an email as a vector for containing spam templates or other malicious content. the organization does not have Exchange spam/content Filter policies to flag emails containing iframes as spam. It is advisable to create content filter rules to detect iframes in email as spam."
		Remediation	     = "Use the PowerShell Script or the References to create a iFrame Spam policy"
		PowerShellScript = 'New-HostedContentFilterPolicy -Name "Example Policy" -HighConfidenceSpamAction Quarantine -SpamAction Quarantine -BulkThreshold 6'
		DefaultValue	 = "0"
		ExpectedValue    = "1 Policy"
		ReturnedValue    = $findings.ToString()
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Configuring Exchange Online Protection, First Steps'; 'URL' = "https://practical365.com/first-steps-configuring-exchange-online-protection/" },
			@{ 'Name' = 'Advanced Spam Filter (ASF) Settings in Exchange Online Protection'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/advanced-spam-filtering-asf-options?view=o365-worldwide" },
			@{ 'Name' = 'Set-HostedContentFilterPolicy Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-hostedcontentfilterpolicy?view=exchange-ps" })
	}
	return $inspectorobject
}

function Inspect-IframesAreSpam
{
	Try
	{
		
		If (-NOT (Get-HostedContentFilterPolicy).MarkAsSpamFramesInHtml)
		{
			$endobject = Build-IframesAreSpam((Get-HostedContentFilterPolicy).MarkAsSpamFramesInHtml)
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

return Inspect-IframesAreSpam


