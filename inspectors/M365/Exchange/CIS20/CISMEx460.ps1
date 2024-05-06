# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure that an anti-phishing policy has been created
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx460($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx460"
		FindingName	     = "CIS MEx 4.6 - Anti-phishing policy not has been created"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "15"
		Description	     = "Protects users from phishing attacks (like impersonation and spoofing), and uses safety tips to warn users about potentially harmful messages."
		Remediation	     = "Rune the following command to create a new AntiPhishPolicy"
		PowerShellScript = '$domains = Get-AcceptedDomain; New-AntiPhishPolicy -Name "AntiPhish Policy" -Enabled $true -EnableOrganizationDomainsProtection $true -EnableSimilarUsersSafetyTips $true -EnableSimilarDomainsSafetyTips $true -EnableUnusualCharactersSafetyTips $true -AuthenticationFailAction Quarantine -EnableMailboxIntelligenceProtection $true -MailboxIntelligenceProtectionAction movetoJMF -PhishThresholdLevel 2 -TargetedUserProtectionAction movetoJMF -EnableTargetedDomainsProtection $true -TargetedDomainProtectionAction MovetoJMF -EnableAntispoofEnforcement $true New-AntiPhishRule -Name "AntiPhish Rule" -AntiPhishPolicy "AntiPhish Policy" -RecipientDomainIs $domains[0]'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "Policy"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Securing Your Office 365 Tenants. Part 2'; 'URL' = "https://www.msp360.com/resources/blog/securing-your-office-365-tenants-part-2/#:~:text=The%20anti%2Dphishing%20settings%20can%20be%20created%20with%20PowerShell%20Exchange%20Online%20commands" }, @{ 'Name' = "Configure anti-phishing policies"; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-anti-phishing-policies?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Inspect-CISMEx460
{
	$AntiPhishPolicyViolation = @()
	Try
	{
		try
		{
			$AntiPhishPolicy = Get-AntiPhishPolicy | ft name, enabled, PhishThresholdLevel, EnableMailboxIntelligenceProtection, EnableMailboxIntelligence, EnableSpoofIntelligence | Where-Object { $_.IsDefault -eq $true }
			if ($AntiPhishPolicy.count -eq 0)
			{
				$AntiPhishPolicy = Get-AntiPhishPolicy | ft name, enabled, PhishThresholdLevel, EnableMailboxIntelligenceProtection, EnableMailboxIntelligence, EnableSpoofIntelligence
			}
			if ($AntiPhishPolicy.enabled -eq $false)
			{
				$AntiPhishPolicyViolation += "Enabled: $($AntiPhishPolicy.enabled)"
			}
			if ($AntiPhishPolicy.PhishThresholdLevel -ilt 2)
			{
				$AntiPhishPolicyViolation += "PhishThresholdLevel: $($AntiPhishPolicy.PhishThresholdLevel)"
			}
			if ($AntiPhishPolicy.EnableMailboxIntelligenceProtection -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableMailboxIntelligenceProtection: $($AntiPhishPolicy.EnableMailboxIntelligenceProtection)"
			}
			if ($AntiPhishPolicy.EnableMailboxIntelligence -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableMailboxIntelligence: $($AntiPhishPolicy.EnableMailboxIntelligence)"
			}
			if ($AntiPhishPolicy.EnableSpoofIntelligence -eq $false)
			{
				$AntiPhishPolicyViolation += "EnableSpoofIntelligence: $($AntiPhishPolicy.EnableSpoofIntelligence)"
			}
		}
		catch
		{
			$AntiPhishPolicyViolation += "No AntiPhish Policy Available"
		}
		
		If ($AntiPhishPolicyViolation.count -igt 0)
		{
			$endobject = Build-CISMEx460($AntiPhishPolicyViolation)
			return $endobject
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx460


