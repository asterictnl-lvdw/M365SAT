# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if ADFS is existing
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex008($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex008"
		FindingName	     = "CSTM-Ex008 - (Multiple) Whitelisted Domains Detected"
		ProductFamily    = "Microsoft Exchange"
		RiskScore		     = "6"
		Description	     = "Whitelisting domains in transport rules bypasses regular malware and phishing scanning, which can enable an attacker to launch attacks against your users from a safe haven domain."
		Remediation	     = "Use the PowerShell script to remove the transport rules"
		PowerShellScript = 'Remove-TransportRule {RuleName}; Get-TransportRule | Where-Object {($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null)} | ft Name,SenderDomainIs'
		DefaultValue	 = "0 Domains"
		ExpectedValue    = "0 Domains"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'CIS 7, 9.7'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" })
	}
	return $inspectorobject
}

function Audit-CSTM-Ex008
{
	try
	{
		$ExchangeDomainWhitelistingData = @()
		$ExchangeDomainWhitelisting = Get-TransportRule | Where-Object { ($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null) } | select Name, SenderDomainIs
		if (-not [string]::IsNullOrEmpty($ExchangeDomainWhitelisting))
		{
			foreach ($ExchangeDomainWhitelistingDataObj in $ExchangeDomainWhitelisting)
			{
				$ExchangeDomainWhitelistingData += "$($ExchangeDomainWhitelisting.Name), $($ExchangeDomainWhitelisting.SenderDomainIs)"
			}
			$endobject = Build-CSTM-Ex008($ExchangeDomainWhitelistingData)
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
return Audit-CSTM-Ex008