# This is an ExchangeModernAuthentication Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Exchange has Modern Authentication Enabled Checks on OAuth2ClientProfileEnabled setting
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Sets Path to OutPath from main file
$path = @($OutPath)

function Build-ExchangeModernAuthentication($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0051"
		FindingName	     = "Exchange Modern Authentication is Not Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.1"
		Description	     = "Modern Authentication is an Exchange feature that allows authentication capabilities such as multi-factor authentication, smart cards, and certificate-based authentication to function. It is recommended that Modern Authentication be enabled for Exchange Online in order to provide these capabilities."
		Remediation	     = "Use the Set-OrganizationConfig PowerShell to enable Modern Authentication for Exchange Online"
		PowerShellScript = 'Set-OrganizationConfig -OAuth2ClientProfileEnabled $true'
		DefaultValue	 = "True"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Enable or disable modern authentication in Exchange Online'; 'URL' = "https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online" },
			@{ 'Name' = 'Set-OrganizationConfig Commandlet Reference'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-organizationconfig?view=exchange-ps" })
	}
	return $inspectorobject
}


function Inspect-ExchangeModernAuthentication
{
	Try
	{
		
		$orgs_without_MA = @()
		Get-OrganizationConfig |
		ForEach-Object -Process { if (!$_.OAuth2ClientProfileEnabled) { $orgs_without_MA += $_.Name; } }
		
		If ($orgs_without_MA.Count -NE 0)
		{
			$endobject = Build-ExchangeModernAuthentication($orgs_without_MA)
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

return Inspect-ExchangeModernAuthentication


