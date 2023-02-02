# This is an ExchangeDomainWhitelisting Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Whitelisted Domains are Detected in Microsoft Exchange
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-ExchangeDomainWhitelisting($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0021"
		FindingName	     = "Whitelisted Domains Detected"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "Anti-Spam, Anti-Phishing and Anti-Malware Policies are recommended to have an existing policy configured to minimize impact from spam and phishing and malware within your organization"
		Remediation	     = "Whitelisting domains in transport rules bypasses regular malware and phishing scanning, which can enable an attacker to launch attacks against your users from a safe haven domain."
		PowerShellScript = 'Remove-TransportRule {RuleName}; Get-TransportRule | Where-Object {($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null)} | ft Name,SenderDomainIs'
		DefaultValue	 = "0 Domains"
		ExpectedValue    = "0 Domains"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'CIS 7, 9.7'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" })
	}
	return $inspectorobject
}

function Audit-ExchangeDomainWhitelisting
{
	try
	{
		$ExchangeDomainWhitelistingData = @()
		$ExchangeDomainWhitelisting = Get-TransportRule | Where-Object { ($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null) } | select Name, SenderDomainIs
		if (!$ExchangeDomainWhitelisting -eq $null)
		{
			foreach ($ExchangeDomainWhitelistingDataObj in $ExchangeDomainWhitelisting)
			{
				$ExchangeDomainWhitelistingData += "$($ExchangeDomainWhitelisting.Name), $($ExchangeDomainWhitelisting.SenderDomainIs)"
			}
			$endobject = Build-ExchangeDomainWhitelisting($ExchangeDomainWhitelistingData)
			return $endobject
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
return Audit-ExchangeDomainWhitelisting