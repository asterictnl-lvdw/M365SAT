# This is an SpamMonitoring Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if SpamMonitoring is activated in Microsoft Exchange
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-SpamMonitoring($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0035"
		FindingName	     = "Suspicious Outgoing Spam Messages Not Monitored"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "2.0"
		Description	     = "The Outbound Spam Policy allows for admins to be sent copies of suspected/suspicious outbound messages that may be spam. This configuration can be used to detect and alert administrators to potentially compromised or abused accounts."
		Remediation	     = "Use the PowerShell Script or the References to create a iFrame Spam policy"
		PowerShellScript = 'Set-HostedOutboundSpamFilterPolicy -BccSuspiciousOutboundMail $true -BccSuspiciousOutboundAdditionalRecipients "administrator@yourdomain"'
		DefaultValue	 = "Not configured policy"
		ExpectedValue    = "A configured policy "
		ReturnedValue    = $findings
		Impact		     = "Low"
		RiskRating	     = "Low"
		References	     = @(@{ 'Name' = 'Set-HostedOutboundSpamFilterPolicy Function Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-hostedoutboundspamfilterpolicy?view=exchange-ps" },
			@{ 'Name' = 'Configure Outbound Spam Notification Office 365 Exchange Online'; 'URL' = "http://www.thatlazyadmin.com/2019/04/01/configure-outbound-spam-notification-office-365-exchange-online/" })
	}
	return $inspectorobject
}


function Inspect-SpamMonitoring
{
	Try
	{
		
		$spamMonitoring = (Get-HostedOutboundSpamFilterPolicy).BccSuspiciousOutboundMail
		
		If ($spamMonitoring -eq $false)
		{
			$endobject = Build-SpamMonitoring("No configured recipients.")
			Return $endobject
		}
		
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

return Inspect-SpamMonitoring


