# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: Checks for Expired Domain Registrations
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az003($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az003"
		FindingName	     = "CSTM-Az003 - Expired Domain Registration(s) Found"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "3"
		Description	     = "Recently a blog was published about a method of tenant takeover using expired domain registrations. This method relied on a domain registration expiring and the domain remaining associated with the Tenant. Monitoring domain registration for the organization can help detect and alert on attempts to exploit this attack path. Microsoft initially issued fixes for this attack between December 2021 and January 2022, but has since rolled back those efforts"
		Remediation	     = "Remediation of this finding requires removing the domain from the list of associated domains within the tenant."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'LetItGo: A Case Study in Expired Domains and Azure AD'; 'URL' = "https://sra.io/blog/letitgo-a-case-study-in-expired-domains-and-azure-ad/" },
			@{ 'Name' = 'DNSense: Brand and Domain Protection Made Simple'; 'URL' = "https://soteria.io/dnsense-online-brand-protection/" })
	}
}

Function Inspect-CSTM-Az003
{
	Try
	{
		
		$domains = Get-MgDomain | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
		
		$results = @()
		
		foreach ($domain in $domains.DomainName)
		{
			try
			{
				$expDate = (Invoke-WebRequest "https://whois.com/whois/$domain" -UseBasicParsing | Select-Object -ExpandProperty RawContent | Select-String -Pattern "Registry Expiry Date: (.*)" -ErrorAction SilentlyContinue).Matches.Groups[1].Value
			}
			catch
			{
				$expDate = $null
			}
			finally
			{
				if ($expDate -ne $null)
				{
					$expDate = ($expDate).Split('T')[0]
					$today = Get-Date -Format yyyy/MM/dd
					If ($expDate -lt $today)
					{
						$results += "$domain - $expDate"
					}
				}
			}
		}
		if ($results -eq $null)
		{
			Return $null
		}
		else
		{
			$endobject = Build-CSTM-Az003($results)
			Return $endobject
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}
Return Inspect-CSTM-Az003


