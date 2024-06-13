# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Exchange
# Purpose: Ensure Priority accounts have 'Strict protection' presets applied
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

function Build-CISMEx244($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx244"
		FindingName	     = "CIS MEx 2.4.4 - Zero-hour auto purge for Microsoft Teams is Off"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "15"
		Description	     = "ZAP is intended to protect users that have received zero-day malware messages or content that is weaponized after being delivered to users. It does this by continually monitoring spam and malware signatures taking automated retroactive action on messages that have already been delivered"
		Remediation	     = "Use the PowerShell Script to enable PriorityAccountProtection"
		PowerShellScript = 'Set-TeamsProtectionPolicy -Identity "Teams Protection Policy" -ZapEnabled $true'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure ZAP for Teams protection in Defender for Office 365 Plan 2'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/mdo-support-teams-about?view=o365-worldwide#configure-zap-for-teams-protection-in-defender-for-office-365-plan-2" },
			@{ 'Name' = 'Zero-hour auto purge (ZAP) in Microsoft Teams'; 'URL' = "https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge?view=o365-worldwide#zero-hour-auto-purge-zap-in-microsoft-teams" })
		}
	return $inspectorobject
}

function Audit-CISMEx244
{		
	try
	{
		# Actual Script
		$AffectedOptions = @()
		
		try{
			$TPP = Get-TeamsProtectionPolicy
			if ($TPP.ZapEnabled -ne $true){
				$AffectedOptions += "ZapEnabled: $($TPP.ZapEnabled)"
			}
			$TPR = Get-TeamsProtectionPolicyRule | fl ExceptIf*
			if (-not [string]::IsNullOrEmpty($TPR.ExpectIf*)){
				$AffectedOptions += "ZapEnabled: $($TPP.ZapEnabled)"
			}
		}catch{

		}
		
		# Validation
		if ($AffectedOptions.Count -ne 0)
		{
			$AffectedOptions | Format-Table -AutoSize | Out-File "$path\CISMEx244-ZAPTEAMSExchange.txt"
			$finalobject = Build-CISMEx244($AffectedOptions)
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
return Audit-CISMEx244