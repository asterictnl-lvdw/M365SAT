# This is an SPFRecords Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if SPFRecords contain Soft Fail
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-SPFSoftFail($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0064"
		FindingName	     = "Domains with SPF Soft Fail Configured"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "The domains listed above have SPF records that are configured with soft failure. Soft failure tells hosts receiving email that falsely purports to be from the organization that they should flag the email as failing a sender verification check, but should still deliver the email. This means that adversaries still have significant leeway to imitate the organization's brand and domains when sending email because many users will still see the fake email even though it failed the sender verification check."
		Remediation	     = "Consider setting the SPF qualifier in the SPF DNS record for the affected domains to '-' (fail) rather than '~' (soft fail). This will help ensure that mail that does not truly originate from the organization's servers will be rejected by the recipients. However, it should be noted that once this action is taken, any mail from the organization's domain which does not pass a sender verification check may automatically be blocked by the recipient's mail servers. This can lead to dropped emails in cases where the organization's own SPF record is not set up properly and has not been adequately tested, causing sender verification failures. For this reason soft failure is often recommended as an intermediate step to test the benefits and configuration of SPF. Always proceed with appropriate caution during SPF rollouts and ensure that the difference between soft and hard failure is fully understood before implementing either."
		PowerShellScript = ''
		DefaultValue	 = "Null for all custom domains"
		ExpectedValue    = "v=spf1 include:spf.protection.outlook.com include:<domain name> -all"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Explaining SPF Records'; 'URL' = "https://postmarkapp.com/blog/explaining-spf" },
			@{ 'Name' = 'Server Fault: Soft Fail over Fail best practices?'; 'URL' = "https://serverfault.com/questions/355511/is-using-softfail-over-fail-in-the-spf-record-considered-best-practice" })
	}
	return $inspectorobject
}

function Inspect-SPFSoftFail
{
	Try
	{
		
		$domains = Get-MgDomain | Where-Object { $_.Id -notlike "*.onmicrosoft.com" }
		$domains_with_soft_fail = @()
		
		ForEach ($domain in $domains.name)
		{
			($spf_record = ((nslookup -querytype=txt $domain 2>&1 | Select-String "spf1") -replace "`t", "")) | Out-Null
			
			If (-NOT ($spf_record -Match "-all"))
			{
				$domains_with_soft_fail += $domain
			}
		}
		
		If ($domains_with_soft_fail.Count -ne 0)
		{
			$endobject = Build-SPFSoftFail($domains_with_soft_fail)
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

return Inspect-SPFSoftFail


