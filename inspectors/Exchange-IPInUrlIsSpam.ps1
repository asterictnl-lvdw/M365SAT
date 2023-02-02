# This is an IPInUrlIsSpam Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if IPInUrl Filtering is active and marks IP adresses that are in emails as SPAM
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-IPInUrlIsSpam($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0038"
		FindingName	     = "No Spam Filters to Flag Emails containing IP Addresses as Spam"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "3.3"
		Description	     = "The organization does not have Exchange Spam/Content Filter policies to flag emails containing IP addresses as spam. Cyber adversaries often send emails that contain the IP addresses of malicious websites or other attack infrastructure. This may occur during phishing or lateral phishing. For this reason it is advisable to create Exchange Transport Rules to detect IP addresses in email as spam."
		Remediation	     = "Use the PowerShell Command to mitigate this issue."
		PowerShellScript = 'Set-HostedContentFilterPolicy -Identity "Default" -AllowedSenderDomains $AllowedSenders -BulkSpamAction MoveToJmf -BulkThreshold 7 -EnableRegionBlockList $true -RegionBlockList "CN","NG","KP","RU","UA","TH","PH","JP","HK","TW" -HighConfidenceSpamAction MoveToJmf -IncreaseScoreWithBizOrInfoUrls On -IncreaseScoreWithNumericIps On -InlineSafetyTipsEnabled $true -MakeDefault -MarkAsSpamBulkMail Off -MarkAsSpamFromAddressAuthFail On -MarkAsSpamNdrBackscatter On -MarkAsSpamSpfRecordHardFail On -PhishSpamAction MoveToJmf -SpamAction MoveToJmf'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = $findings
		Impact		     = "Low"
		RiskRating	     = "Low"
		References	     = @(@{ 'Name' = 'Configuring Exchange Online Protection, First Steps'; 'URL' = "https://practical365.com/first-steps-configuring-exchange-online-protection/" },
			@{ 'Name' = 'Anti-Spam Settings With Region Blocking'; 'URL' = "https://www.msp360.com/resources/blog/securing-your-office-365-tenants-part-2/#:~:text=Safe%20Links%20Policy%27-,Anti%2DSpam%20Settings%20With%20Region%20Blocking,-Next%20up%20is" })
	}
	return $inspectorobject
}

function Inspect-IPInUrlIsSpam
{
	Try
	{
		$policies = Get-HostedContentFilterPolicy
		
		$settingOff = @()
		
		$settingOn = @()
		
		Foreach ($policy in $policies)
		{
			If ($policy.IncreaseScoreWithNumericIps -eq "On")
			{
				$settingOn += $policy.Name
			}
			elseif ($policy.IncreaseScoreWithNumericIps -ne "On")
			{
				$settingOff += "$($policy.Name): $($policy.IncreaseScoreWithNumericIps)"
			}
		}
		
		If (($settingOn | Measure-Object).Count -eq 0)
		{
			$endobject = Build-IPInUrlIsSpam($settingOff)
			return $endobject
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

return Inspect-IPInUrlIsSpam


