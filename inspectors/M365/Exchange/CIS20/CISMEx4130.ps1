# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Priority account protection is enabled and configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMEx4130($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx4130"
		FindingName	     = "CIS MEx 4.13 - Priority accounts do not have 'Strict protection' presets applied"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "15"
		Description	     = "Enabling priority account protection for users in Microsoft 365 is necessary to enhance security for accounts with access to sensitive data and high privileges, such as CEOs, CISOs, CFOs, and IT admins. These priority accounts are often targeted by spear phishing or whaling attacks and require stronger protection to prevent account compromise. To address this, Microsoft 365 and Microsoft Defender for Office 365 offer several key features that provide extra security, including the identification of incidents and alerts involving priority accounts and the use of built-in custom protections designed specifically for them."
		Remediation	     = "Use the PowerShell Script to enable PriorityAccountProtection"
		PowerShellScript = 'Enable-EOPProtectionPolicyRule -Identity "Strict Preset Security Policy"; Enable-ATPProtectionPolicyRule -Identity "Strict Preset Security Policy"'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Manage and monitor priority accounts'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/setup/priority-accounts?view=o365-worldwide" },
			@{ 'Name' = 'Preset security policies in EOP and Microsoft Defender for Office 365'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide" },
			@{ 'Name' = 'Recommended settings for EOP and Microsoft Defender for Office 365 security'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365?view=o365-worldwide#impersonation-settings-in-anti-phishing-policies-in-microsoft-defender-for-office-365" },
			@{ 'Name' = 'Security recommendations for priority accounts in Microsoft 365'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/priority-accounts-security-recommendations?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMEx4130
{
	# https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/preset-security-policies?view=o365-worldwide
	
	
	
	try
	{
		# Actual Script
		$AffectedOptions = @()
		#AntiPhishPolicy (AntiPhishing)
		try
		{
			$Policy1 = AntiPhishPolicy -ErrorAction SilentlyContinue | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy1))
			{
				$AffectedOptions += "No Strict AntiPhishPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict AntiPhishPolicy Available"
		}
		#MalwareFilterPolicy (Anti-Malware)
		try
		{
			$Policy2 = MalwareFilterPolicy -ErrorAction SilentlyContinue | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy2))
			{
				$AffectedOptions += "No Strict MalwareFilterPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict MalwareFilterPolicy Available"
		}
		#HostedContentFilterPolicy (Anti-Spam)
		try
		{
			$Policy3 = HostedContentFilterPolicy -ErrorAction SilentlyContinue | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy3))
			{
				$AffectedOptions += "No Strict HostedContentFilterPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict HostedContentFilterPolicy Available"
		}
		#SafeAttachmentPolicy (SafeAttachments)
		try
		{
			$Policy4 = SafeAttachmentPolicy -ErrorAction SilentlyContinue | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy4))
			{
				$AffectedOptions += "No Strict SafeAttachmentPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict SafeAttachmentPolicy Available"
		}
		#SafeLinksPolicy (SafeLinks)
		try
		{
			$Policy5 = SafeLinksPolicy | Where-Object -Property RecommendedPolicyType -eq -Value "Strict"
			if ([string]::IsNullOrEmpty($Policy5))
			{
				$AffectedOptions += "No Strict SafeLinksPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict SafeLinksPolicy Available"
		}
		#EOPProtectionPolicyRule
		try
		{
			$Policy6 = Get-EOPProtectionPolicyRule -Identity "Strict Preset Security Policy" -ErrorAction SilentlyContinue
			if ([string]::IsNullOrEmpty($Policy5))
			{
				$AffectedOptions += "No Strict EOPProtectionPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict EOPProtectionPolicy Available"
		}
		#ATPProtectionPolicyRule
		try
		{
			$Policy7 = Get-ATPProtectionPolicyRule -Identity "Strict Preset Security Policy" -ErrorAction SilentlyContinue
			if ([string]::IsNullOrEmpty($Policy5))
			{
				$AffectedOptions += "No Strict ATPProtectionPolicy Available"
			}
		}
		catch
		{
			$AffectedOptions += "No Strict ATPProtectionPolicy Available"
		}
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$finalobject = Build-CISMEx4130($AffectedOptions)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx4130