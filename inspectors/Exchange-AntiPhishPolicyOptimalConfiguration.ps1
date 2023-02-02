# This is an AntiPhishPolicyOptimalConfiguration Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the AntiPhishPolicy is optimally configured according to CIS-standards.
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

$path = @($OutPath)

function Build-AntiPhishPolicyOptimalConfiguration($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0005"
		FindingName	     = "Anti Phish Policy Not Configured Properly"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.3"
		Description	     = "Domain Spoofing occurs when an external entity sends email using a mail domain owned by another entity. There are legitimate use cases where domain spoofing is allowed. It is recommended to speak with stakeholders and determine if this type of rule is beneficial and if any exceptions are needed. Microsoft configures some Anti-Spoofing settings by default in the Anti-Phishing policies on tenants, this rule would complement default settings."
		Remediation	     = "Execute the PowerShell Script to optimally configure the AntiPhish Policy for your tenant"
		PowerShellScript = '$domains = Get-AcceptedDomain;New-AntiPhishPolicy -Name "AntiPhish Policy" -Enabled $true -EnableOrganizationDomainsProtection $true ?-EnableSimilarUsersSafetyTips $true -EnableSimilarDomainsSafetyTips $true -EnableUnusualCharactersSafetyTips $true -AuthenticationFailAction Quarantine -EnableMailboxIntelligenceProtection $true -MailboxIntelligenceProtectionAction movetoJMF -PhishThresholdLevel 2 -TargetedUserProtectionAction movetoJMF -EnableTargetedDomainsProtection $true -TargetedDomainProtectionAction MovetoJMF -EnableAntispoofEnforcement $true New-AntiPhishRule -Name "AntiPhish Rule" -AntiPhishPolicy "AntiPhish Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "Disabled All"
		ExpectedValue    = "Enabled All"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Set-AntiPhishPolicy'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/exchange/set-antiphishpolicy?view=exchange-ps' })
	}
	return $inspectorobject
}

function Audit-AntiPhishPolicyOptimalConfiguration
{
	try
	{
		$finalobject = @()
		#Checks if AntiPhish Policies have a optimal configuration
		$AntiPhishPolicies = Get-AntiPhishPolicy | where Enabled -eq $True | select Name, Enabled, EnableTargetedUserProtection, EnableMailboxIntelligenceProtection, EnableTargetedDomainsProtection, EnableOrganizationDomainsProtection, EnableMailboxIntelligence, EnableFirstContactSafetyTips, EnableSimilarUsersSafetyTips, EnableSimilarDomainsSafetyTips, EnableUnusualCharactersSafetyTips
		foreach ($AntiPhishPolicy in $AntiPhishPolicies)
		{
			$finalobject += $AntiPhishPolicy.Name
			$array = @("EnableTargetedUserProtection", "EnableMailboxIntelligenceProtection", "EnableTargetedDomainsProtection", "EnableOrganizationDomainsProtection", "EnableMailboxIntelligence", "EnableFirstContactSafetyTips", "EnableSimilarUsersSafetyTips", "EnableSimilarDomainsSafetyTips", "EnableUnusualCharactersSafetyTips")
			foreach ($object in $array)
			{
				if ($AntiPhishPolicy.$object -eq $false)
				{
					$object = "$($object): $($AntiPhishPolicy.$object)"
					$finalobject += $object
				}
			}
		}
		if ($finalobject.Count -ne 0)
		{
			$endobject = Build-AntiPhishPolicyOptimalConfiguration($sendingInfrastructure)
			return $endobject
		}
		else
		{
			return $null
		}
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

return Audit-AntiPhishPolicyOptimalConfiguration