# This is an CustomAntiPhishingPolicy Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks AntiPhish policies are correctly configured
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-CustomAntiPhishingPolicy($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0018"
		FindingName	     = "No Custom Anti-Phishing Policy Present"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "It is possible to create custom Anti-Phishing Policies in Exchange Online to provide additional protection against threats that may be received via email. No Anti-Phishing Policy besides the Microsoft Default Anti-Phishing Policy was detected in the O365 tenant. Although the default Anti-Phishing Policy can provide some protection, each organization should consider creating an Anti-Phishing Policy that is customized to suit the nature of their day-to-day activities."
		Remediation	     = "Follow Securing Your Office 365 Tenants. Part 2 and use the template to create a AntiPhishPolicy for your organization."
		PowerShellScript = '$domains = Get-AcceptedDomain;New-AntiPhishPolicy -Name "AntiPhish Policy" -Enabled $true -EnableOrganizationDomainsProtection $true ?-EnableSimilarUsersSafetyTips $true -EnableSimilarDomainsSafetyTips $true -EnableUnusualCharactersSafetyTips $true -AuthenticationFailAction Quarantine -EnableMailboxIntelligenceProtection $true -MailboxIntelligenceProtectionAction movetoJMF -PhishThresholdLevel 2 -TargetedUserProtectionAction movetoJMF -EnableTargetedDomainsProtection $true -TargetedDomainProtectionAction MovetoJMF -EnableAntispoofEnforcement $true New-AntiPhishRule -Name "AntiPhish Rule" -AntiPhishPolicy "AntiPhish Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "> 0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'Securing Your Office 365 Tenants. Part 2'; 'URL' = "https://www.msp360.com/resources/blog/securing-your-office-365-tenants-part-2/#:~:text=The%20anti%2Dphishing%20settings%20can%20be%20created%20with%20PowerShell%20Exchange%20Online%20commands" }, @{ 'Name' = "Configure anti-phishing policies"; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-anti-phishing-policies?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Inspect-CustomAntiPhishingPolicy
{
	Try
	{
		
		If (-NOT (Get-AntiPhishPolicy | Where-Object { !$_.IsDefault }))
		{
			$endobject = Build-CustomAntiPhishingPolicy("0")
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

return Inspect-CustomAntiPhishingPolicy


