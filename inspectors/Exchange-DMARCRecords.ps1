# This is an DMARCRecords Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if DMARC Records exist
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-DMARCRecords($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0072"
		FindingName	     = "Domains with no DMARC Records"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "No Domain-based Message Authentication, Reporting and Conformance (DMARC) records are present for the domains listed. DMARC is a security control that builds atop Sender Policy Framework and Domain-Keys Identified Mail to help control concerns related to the use of the organization's domain in malicious emails (email spoofing)."
		Remediation	     = "Understand that DMARC cannot be implemented until SPF and DKIM are, as DMARC extends them. Consider reviewing the organization's implementation of SPF and DKIM. If the organization is ready to implement DMARC, review the references on DMARC implementation below to begin planning a DMARC rollout."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "False for all Custom Domains"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Use DMARC to validate email'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dmarc-to-validate-email?view=o365-worldwide" },
			@{ 'Name' = 'DMARC Overview, Anatomy of a DMARC Record, How Senders Deploy DMARC in 5 Steps'; 'URL' = "https://dmarc.org/overview/" },
			@{ 'Name' = 'What is a DMARC record?'; 'URL' = "https://mxtoolbox.com/dmarc/details/what-is-a-dmarc-record" })
	}
}


function Inspect-DMARCRecords
{
	Try
	{
		
		$domains = Get-MgDomain | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
		$domains_without_records = @()
		
		ForEach ($domain in $domains.Id)
		{
			($dmarc_record = ((nslookup -querytype=txt _dmarc.$domain 2>&1 | Select-String "DMARC1") -replace "`t", "")) | Out-Null
			
			If (-NOT $dmarc_record)
			{
				$domains_without_records += $domain
			}
		}
		
		If ($domains_without_records.Count -ne 0)
		{
			$endobject = Build-DMARCRecords($domains_without_records)
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

return Inspect-DMARCRecords


