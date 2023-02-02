# This is an Basic-Authentication Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the Basic-Authentication is enabled in Microsoft Exchange
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-Basic-Authentication($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0012"
		FindingName	     = "No Policy Detected for Multiple Accounts.  Basic Authentication exists for multiple accounts! Or there is not policy available at the moment."
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.1"
		Description	     = "Legacy authentication protocols do not support multi-factor authentication. These protocols are often used by attackers because of this deficiency."
		Remediation	     = "Disabling Basic Authentication and enforcing Modern Authentication is the only way to remediate this finding. Microsoft plans to forcefully disable Basic Auth on all tenants on October 1, 2022 - regardless of the protocols in use."
		PowerShellScript = 'New-AuthenticationPolicy -Name "Block Basic Auth";Set-OrganizationConfig -DefaultAuthenticationPolicy "Block Basic Auth"; Get-User -ResultSize unlimited | Set-User -AuthenticationPolicy "Block Basic Auth"; Set-OrganizationConfig -DefaultAuthenticationPolicy "Block Basic Auth"'
		DefaultValue	 = "No Policy"
		ExpectedValue    = "An Authentication Policy"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = '6.3 - Require MFA for Externally-Exposed Applications' }, @{ 'Name' = 'CIS_Microsoft_365_Foundations_Benchmark_v1.4.0.pdf'; 'URL' = '9.2 - Ensure Only Approved Ports, Protocols and Services Are Running' })
	}
	return $inspectorobject
}

function Audit-Basic-Authentication
{
	try
	{
		$basicauthdata = @()
		$basicauth1 = Get-OrganizationConfig | Select-Object -ExpandProperty DefaultAuthenticationPolicy | ForEach { Get-AuthenticationPolicy $_ | Select-Object AllowBasicAuth* }
		$basicauth2 = Get-OrganizationConfig | Select-Object DefaultAuthenticationPolicy
		$basicauth3 = Get-User -ResultSize Unlimited | Select-Object UserPrincipalName, AuthenticationPolicy
		if ($basicauth1.DefaultAuthenticationPolicy -contains "" -and $basicauth2.DefaultAuthenticationPolicy -contains "" -and $basicauth3.AuthenticationPolicy -contains "")
		{
			foreach ($basicauthuser in $basicauth3)
			{
				$basicauthdata += "$($basicauth3.UserPrincipalName), $($basicauth3.AuthenticationPolicy)"
			}
			$endobject = Build-Basic-Authentication($basicauthdata)
			return $endobject
		}
		return $null
	}
	catch
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
return Audit-Basic-Authentication