# This is an AntiPhishPolicy Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the AntiPhish Policy is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-AntiPhishPolicy($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0004"
		FindingName	     = "No Phishing Policy Detected!"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.3"
		Description	     = "Your organization is not protecting users from phishing attacks (like impersonation and spoofing) at the moment. This could lead to possible phishing and serious damage to your organization, enabling should display safety tips to warn users about potentially harmful messages."
		Remediation	     = "Use the PowerShell script to create an AntiPhish Policy"
		PowerShellScript = '$domains = Get-AcceptedDomain;New-AntiPhishPolicy -Name "AntiPhish Policy" -Enabled $true -EnableOrganizationDomainsProtection $true ?-EnableSimilarUsersSafetyTips $true -EnableSimilarDomainsSafetyTips $true -EnableUnusualCharactersSafetyTips $true -AuthenticationFailAction Quarantine -EnableMailboxIntelligenceProtection $true -MailboxIntelligenceProtectionAction movetoJMF -PhishThresholdLevel 2 -TargetedUserProtectionAction movetoJMF -EnableTargetedDomainsProtection $true -TargetedDomainProtectionAction MovetoJMF -EnableAntispoofEnforcement $true New-AntiPhishRule -Name "AntiPhish Rule" -AntiPhishPolicy "AntiPhish Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "None"
		ExpectedValue    = "AntiPhishPolicy"
		ReturnedValue    = "No AntiPhish Policy Available"
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = 'https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf' }, @{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = 'https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf' })
	}
	return $inspectorobject
}

function Audit-AntiPhishPolicy
{
	try
	{
		Import-Module ExchangeOnlineManagement
		$AntiPhishPolicy = Get-AntiPhishPolicy | select Name
		if ($AntiPhishPolicy.Name -eq $null)
		{
			$finalobject = Build-AntiPhishPolicy($sendingInfrastructure)
			return $finalobject
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
return Audit-AntiPhishPolicy