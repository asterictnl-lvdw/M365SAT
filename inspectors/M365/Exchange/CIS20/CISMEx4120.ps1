# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Priority account protection is enabled and configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMEx4120($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx4120"
		FindingName	     = "CIS MEx 4.12 - Priority account protection is not enabled and configured!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "15"
		Description	     = "Enabling priority account protection for users in Microsoft 365 is necessary to enhance security for accounts with access to sensitive data and high privileges, such as CEOs, CISOs, CFOs, and IT admins. These priority accounts are often targeted by spear phishing or whaling attacks and require stronger protection to prevent account compromise. To address this, Microsoft 365 and Microsoft Defender for Office 365 offer several key features that provide extra security, including the identification of incidents and alerts involving priority accounts and the use of built-in custom protections designed specifically for them."
		Remediation	     = "Use the PowerShell Script to enable PriorityAccountProtection"
		PowerShellScript = 'Set-EmailTenantSettings -EnablePriorityAccountProtection $true'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Manage and monitor priority accounts'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/admin/setup/priority-accounts?view=o365-worldwide" },
			@{ 'Name' = 'Manage and monitor priority accounts'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/priority-accounts-security-recommendations?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMEx4120
{
	try
	{
		# Actual Script
		$AffectedOptions = @()
		$ExchangeSetting = Get-EmailTenantSettings | Format-List Identity, EnablePriorityAccountProtection
		if ($ExchangeSetting.EnablePriorityAccountProtection -ne $true)
		{
			$AffectedOptions += "EnablePriorityAccountProtection: $($ExchangeSetting.EnablePriorityAccountProtection)"
		}
		
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$finalobject = Build-CISMEx4120($AffectedOptions)
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
return Audit-CISMEx4120