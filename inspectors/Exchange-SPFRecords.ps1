# This is an SPFRecords Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Domains contain a SPFRecord
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-SPFRecords($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0063"
		FindingName	     = "Domains with No SPF Records"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "The domains listed above do not have Sender Policy Framework (SPF) records. SPF records can be used by receiving mail servers to identify whether mail that purports to be from the organization's domains is actually from the organization's domains, or spoofed by an adversary. This helps defeat common tactics adversaries use during phishing and other offensive activities such as spoofing email addresses that mimic the organization's domain."
		Remediation	     = "Create an SPF TXT DNS record as described in the references below. Remember that configuring SPF may affect the deliverability of mail from that domain. An SPF rollout should be measured and gradual."
		PowerShellScript = ''
		DefaultValue	 = "Null for all custom domains"
		ExpectedValue    = "v=spf1 include:spf.protection.outlook.com include:<domain name> -all"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Set Up SPF in Office 365 to Help Prevent Spoofing'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing?view=o365-worldwide" },
			@{ 'Name' = 'Explaining SPF Records'; 'URL' = "https://postmarkapp.com/blog/explaining-spf" })
	}
	return $inspectorobject
}


function Inspect-SPFRecords
{
	Try
	{
		
		$domains = Get-MgDomain | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
		$domains_without_records = @()
		
		# The redirection is kind of a cheesy hack to prevent the output from
		# cluttering the screen.
		ForEach ($domain in $domains.Name)
		{
			($spf_record = ((nslookup -querytype=txt $domain 2>&1 | Select-String "spf1") -replace "`t", "")) | Out-Null
			
			If (-NOT $spf_record)
			{
				$domains_without_records += $domain
			}
		}
		
		If ($domains_without_records.Count -ne 0)
		{
			$endobject = Build-SPFRecords($domains_without_records)
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

return Inspect-SPFRecords


