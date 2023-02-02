# This is an DKIMRecordsSelector2 Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks DKIM Records exist
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-DKIMRecordsSelector2($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0070"
		FindingName	     = "Domains with No DKIM Selector 2 DNS Record"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "DKIM is a technology that uses public-key cryptography as a tool to help assure the integrity of emails as they are sent between servers. Additionally, cyber adversaries are known to sometimes generate spoofed (falsified) emails that appear to originate from the organization. DKIM can also enable recipients to distinguish spoofed email from authentic email originating from the domain, therefore increasing trust in the domain and ideally reducing the likelihood that members of the organization or related organizations will be successfully phished by imitative attacks. The domains listed above do not have a DKIM Selector1 DNS record. A Selector1 record is one of two DKIM-related records necessary to successfully implement DKIM in conjunction with O365."
		Remediation	     = "Follow the guide in the References section to learn the full significance of the DKIM Selector1 record to O365 DKIM configuration. DKIM rollout can be a very involved process, for which there is a complete reference in the 'Use DKIM to validate the outbound email sent from your custom domain' guide in the References section below."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "False for all custom domains"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Use DKIM to validate outbound email sent from your custom domain'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email?view=o365-worldwide" },
			@{ 'Name' = 'Set-DkimSigningConfig Command Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-dkimsigningconfig?view=exchange-ps" },
			@{ 'Name' = 'DKIM FAQ'; 'URL' = "http://dkim.org/info/dkim-faq.html" })
	}
}


function Inspect-DKIMRecordsSelector2
{
	Try
	{
		
		$domains = Get-MgDomain | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
		$domains_without_records = @()
		
		ForEach ($domain in $domains.Id)
		{
			($dkim_two_output = (nslookup -querytype=cname selector2._domainkey.$domain 2>&1 | Select-String "canonical name")) | Out-Null
			
			If (-NOT $dkim_two_output)
			{
				$domains_without_records += $domain
			}
		}
		
		If (($domains_without_records | Measure-Object).Count -ne 0)
		{
			$endobject = Build-DKIMRecordsSelector2($domains_without_records)
			Return $endobject
		}
		
		return $null
		
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

return Inspect-DKIMRecordsSelector2


