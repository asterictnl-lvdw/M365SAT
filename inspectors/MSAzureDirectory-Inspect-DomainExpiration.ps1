# This is an DomainExpiration Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Domains are expired within the tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-DomainExpiration($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0012"
		FindingName	     = "Expired Domain Registration Found"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "8.5"
		Description	     = "Recently a blog was published about a method of tenant takeover using expired domain registrations. This method relied on a domain registration expiring and the domain remaining associated with the Tenant. Monitoring domain registration for the organization can help detect and alert on attempts to exploit this attack path. Microsoft initially issued fixes for this attack between December 2021 and January 2022, but has since rolled back those efforts"
		Remediation	     = "Remediation of this finding requires removing the domain from the list of associated domains within the tenant."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'https://sra.io/blog/letitgo-a-case-study-in-expired-domains-and-azure-ad/'; 'URL' = "https://sra.io/blog/letitgo-a-case-study-in-expired-domains-and-azure-ad/" },
			@{ 'Name' = 'DNSense: Brand and Domain Protection Made Simple'; 'URL' = "https://soteria.io/dnsense-online-brand-protection/" })
	}
}

Function Inspect-DomainExpiration
{
	Try
	{
		
		$domains = Get-AcceptedDomain | Where-Object { $_.Name -notlike "*.onmicrosoft.com" }
		
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
			$endobject = Build-DomainExpiration($results)
			Return $endobject
		}
		
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
Return Inspect-DomainExpiration


