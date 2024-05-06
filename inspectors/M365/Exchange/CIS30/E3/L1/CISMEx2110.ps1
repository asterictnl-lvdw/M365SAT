# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure that DMARC records are published for all Exchange Domains
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2110($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx2110"
		FindingName	     = "CIS MEx 2.1.10 - DMARC Records are not published for all Exchange Domains"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "9"
		Description	     = "Domain-based Message Authentication, Reporting and Conformance (DMARC) work with Sender Policy Framework (SPF) and DomainKeys Identified Mail (DKIM) to authenticate mail senders and ensure that destination email systems trust messages sent from your domain."
		Remediation	     = "Understand that DMARC cannot be implemented until SPF and DKIM are, as DMARC extends them. Consider reviewing the organization's implementation of SPF and DKIM. If the organization is ready to implement DMARC, review the references on DMARC implementation below to begin planning a DMARC rollout."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "False for all Custom Domains"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Use DMARC to validate email'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email?view=o365-worldwide" },
			@{ 'Name' = 'DMARC Overview, Anatomy of a DMARC Record, How Senders Deploy DMARC in 5 Steps'; 'URL' = "https://dmarc.org/overview/" },
			@{ 'Name' = 'What is a DMARC record?'; 'URL' = "https://mxtoolbox.com/dmarc/details/what-is-a-dmarc-record" },
			@{ 'Name' = 'DMARC Configuration'; 'URL' = "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure?view=o365-worldwide" })
	}
}


function Inspect-CISMEx2110
{	
	Try
	{
		$domains = (Get-AcceptedDomain).DomainName | Where-Object { $_ -notlike "*.onmicrosoft.com" }
		$domains_without_records = @()
		ForEach ($domain in $domains.Name)
		{
			try
			{
				$dmarc_record = (Resolve-DnsName -Name $domain -Type TXT | Where-Object { $_.Strings -match 'v=DMARC1' }).Strings
				if ([string]::IsNullOrEmpty($dmarc_record) -eq $true)
				{
					$domains_without_records += $domain
				}
			}
			catch
			{
				$domains_without_records += $domain
			}
		}
		
		If ($domains_without_records.Count -ne 0)
		{
			$domains_without_records | Format-Table -AutoSize | Out-File "$path\CISMEx2110-DomainsWithoutDMARC.txt"
			$endobject = Build-CISMEx2110($domains_without_records)
			Return $endobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx2110


