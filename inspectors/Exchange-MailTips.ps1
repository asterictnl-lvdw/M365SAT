# This is an ExchangeMailTips Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Exchange has MailTips Enabled to help end-users when creating mails
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-ExchangeMailTips($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0050"
		FindingName	     = "ExchangeMailTips: one of the settings is not properly configured"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "MailTips assist end users with identifying strange patterns to emails they send. By having this disabled end-users are at risk exfiltrating information or doing malicious things without knowing or without being warned."
		Remediation	     = "Run the PowerShell Command to enable MailTips"
		PowerShellScript = 'Set-OrganizationConfig -MailTipsAllTipsEnabled $true -MailTipsExternalRecipientsTipsEnabled $true -MailTipsGroupMetricsEnabled $true -MailTipsLargeAudienceThreshold "25"'
		DefaultValue	 = "MailTipsAllTipsEnabled: False <br/> MailTipsExternalRecipientsTipsEnabled: False <br/> MailTipsGroupMetricsEnabled: False <br/> MailTipsLargeAudienceThreshold: 25"
		ExpectedValue    = "MailTipsAllTipsEnabled: True <br/> MailTipsExternalRecipientsTipsEnabled: True <br/> MailTipsGroupMetricsEnabled: True <br/> MailTipsLargeAudienceThreshold: >25"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" },
			@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" },
			@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" })
	}
	return $inspectorobject
}

function Audit-ExchangeMailTips
{
	try
	{
		Import-Module ExchangeOnlineManagement
		$ExchangeMailTipsData = @()
		$ExchangeMailTips = Get-OrganizationConfig | Select-Object MailTipsAllTipsEnabled, MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled, MailTipsLargeAudienceThreshold
		if ($ExchangeMailTips.MailTipsAllTipsEnabled -match 'True' -or $ExchangeMailTips.MailTipsExternalRecipientsTipsEnabled -match 'True' -or $ExchangeMailTips.MailTipsGroupMetricsEnabled -match 'True' -and $ExchangeMailTips.MailTipsLargeAudienceThreshold -ige 25)
		{
			$ExchangeMailTipsData += " MailTipsAllTipsEnabled: " + $ExchangeMailTips.MailTipsAllTipsEnabled
			$ExchangeMailTipsData += "`n MailTipsExternalRecipientsTipsEnabled: " + $ExchangeMailTips.MailTipsExternalRecipientsTipsEnabled
			$ExchangeMailTipsData += "`n MailTipsGroupMetricsEnabled: " + $ExchangeMailTips.MailTipsGroupMetricsEnabled
			$ExchangeMailTipsData += "`n MailTipsLargeAudienceThreshold: " + $ExchangeMailTips.MailTipsLargeAudienceThreshold
			$endobject = Build-ExchangeMailTips($ExchangeMailTipsData)
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
return Audit-ExchangeMailTips