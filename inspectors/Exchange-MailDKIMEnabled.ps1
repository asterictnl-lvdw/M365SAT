# This is an MailDKIMEnabled Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Exchange has DKIM Enabled for Mail Exchange Transportation
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-MailDKIMEnabled($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0049"
		FindingName	     = "DKIM Not Enabled for Exchange Online Domains"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "7.5"
		Description	     = "DKIM (DomainKeys Identified Mail) is not enabled within O365 for the Exchange Online domains listed above. DKIM is a technology that uses public-key cryptography as a tool to help assure the integrity of emails as they are sent between servers. Additionally, cyber adversaries are known to sometimes generate spoofed (falsified) emails that appear to originate from the organization's domains. DKIM can also enable recipients to distinguish spoofed email from authentic email originating from the domain, therefore increasing trust in the domain and ideally reducing the likelihood that members of the organization or related organizations will be successfully phished by imitative attacks. Depending on the  organization's strategy for sender verification and other email security topics, consider enabling DKIM for O365 domains."
		Remediation	     = "DKIM rollout can be a very involved process, for which there is a complete reference in the 'Use DKIM to validate the outbound email sent from your custom domain' guide in the References section below. This finding refers specifically to enabling the DKIM signing configuration within O365 itself, which can be done using the Set-DkimSigningConfig PowerShell function or the Security and Compliance Center in the O365 administration portal."
		PowerShellScript = ''
		DefaultValue	 = "False on all custom domains"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Use DKIM to validate outbound email sent from your custom domain'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email?view=o365-worldwide" },
			@{ 'Name' = 'Set-DkimSigningConfig Command Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-dkimsigningconfig?view=exchange-ps" },
			@{ 'Name' = 'DKIM FAQ'; 'URL' = "http://dkim.org/info/dkim-faq.html" })
	}
	return $inspectorobject
}

function Inspect-MailDKIMEnabled
{
	Try
	{
		
		$domains_without_dkim = (Get-DkimSigningConfig | Where-Object { (!$_.Enabled) -and ($_.Domain -notlike "*.onmicrosoft.com") }).Domain
		
		If ($domains_without_dkim.Count -NE 0)
		{
			$endobject = Build-MailDKIMEnabled($domains_without_dkim)
			Return $endobject
		}
		
		Return $null
		
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

return Inspect-MailDKIMEnabled


