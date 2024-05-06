# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Checks common malicious attachments and if they are filtered properly
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx430($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx430"
		FindingName	     = "CIS MEx 4.3 - Forms of mail forwarding are not blocked and/or not disabled"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "6"
		Description	     = "Attackers often create these rules to exfiltrate data from your tenancy, this could be accomplished via access to an end-user account or otherwise. An insider could also use one of these methods as an secondary channel to exfiltrate sensitive data."
		Remediation	     = "Check all Transport Rules and run the powershell command to remove them:"
		PowerShellScript = 'Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | ft Name,RedirectMessageTo | Remove-TransportRule $_.Name'
		DefaultValue	 = "AllowedOOFType: External <br> AutoForwardEnabled: True"
		ExpectedValue    = "AllowedOOFType: Not External <br> AutoForwardEnabled: False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Procedures for mail flow rules in Exchange Server'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mail-flow-rules/mail-flow-rule-procedures?view=exchserver-2019' },
			@{ 'Name' = 'Control automatic external email forwarding in Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/outbound-spam-policies-external-email-forwarding?view=o365-worldwide' },
			@{ 'Name' = 'All you need to know about automatic email forwarding in Exchange Online'; 'URL' = 'https://techcommunity.microsoft.com/t5/exchange-team-blog/all-you-need-to-know-about-automatic-email-forwarding-in/ba-p/2074888#:~:text=%20%20%20Automatic%20forwarding%20option%20%20,%' })
	}
	return $inspectorobject
}

function Audit-CISMEx430
{
	try
	{
		$TransportRules = Get-TransportRule | Where-Object { $_.RedirectMessageTo -ne $null } | ft Name, RedirectMessageTo
		if ($TransportRules.Count -igt 0)
		{
			$TransportRules | Format-List | Out-File -FilePath "$path\CISMEx430-AffectedTransportRules.txt"
			$finalobject = Build-CISMEx430($TransportRules)
			return $finalobject
		}
		else
		{
			return $null
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISMEx430