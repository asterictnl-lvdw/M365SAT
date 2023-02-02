# This is an BasicAuthConfig Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if Basic Authentication is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-BasicAuthConfig($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0011"
		FindingName	     = "Basic Authentication is Enabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.1"
		Description	     = "Basic Authentication protocols send usernames and passwords in requests, usually with very simple Base64 encoding, making it trivial to capture and decode user credentials. Basic Authentication may be necessary for some legacy software but is unable to enforce MFA and Microsoft has replaced it with Modern Authentication in their offerings."
		Remediation	     = "Disabling Basic Authentication and enforcing Modern Authentication is the only way to remediate this finding. Microsoft plans to forcefully disable Basic Auth on all tenants on October 1, 2022 - regardless of the protocols in use."
		PowerShellScript = 'New-AuthenticationPolicy -Name "Block Basic Auth";Set-OrganizationConfig -DefaultAuthenticationPolicy "Block Basic Auth"; Get-User -ResultSize unlimited | Set-User -AuthenticationPolicy "Block Basic Auth"; Set-OrganizationConfig -DefaultAuthenticationPolicy "Block Basic Auth"'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Upcoming changes to Exchange Web Services (EWS) API for Office 365'; 'URL' = 'https://techcommunity.microsoft.com/t5/exchange-team-blog/upcoming-changes-to-exchange-web-services-ews-api-for-office-365/ba-p/608055' },
			@{ 'Name' = 'Basic Authentication and Exchange Online - September 2021 Update'; 'URL' = 'https://techcommunity.microsoft.com/t5/exchange-team-blog/basic-authentication-and-exchange-online-september-2021-update/ba-p/2772210' },
			@{ 'Name' = 'Enable or disable modern authentication for Outlook in Exchange Online'; 'URL' = 'https://docs.microsoft.com/en-us/exchange/clients-and-mobile-in-exchange-online/enable-or-disable-modern-authentication-in-exchange-online' },
			@{ 'Name' = 'Office 365: Enable Modern Authentication'; 'URL' = 'https://social.technet.microsoft.com/wiki/contents/articles/36101.office-365-enable-modern-authentication.aspx' })
	}
	return $inspectorobject
}


Function Get-BasicAuthConfig
{
	Try
	{
		
		$authMethods = @("AllowBasicAuthActiveSync", "AllowBasicAuthAutodiscover", "AllowBasicAuthImap", "AllowBasicAuthMapi", "AllowBasicAuthOfflineAddressBook", "AllowBasicAuthOutlookService", "AllowBasicAuthPop", "AllowBasicAuthReportingWebServices", "AllowBasicAuthRest", "AllowBasicAuthRpc", "AllowBasicAuthSmtp", "AllowBasicAuthWebServices", "AllowBasicAuthPowershell")
		
		$authPolicy = Get-AuthenticationPolicy
		
		$methods = @()
		foreach ($method in $authMethods)
		{
			If ($authPolicy.$method -eq $true)
			{
				$methods += $method
			}
		}
		If (!$methods)
		{
			Return $null
		}
		$endobject = Build-BasicAuthConfig($methods)
		return $endobject
		
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

Return Get-BasicAuthConfig


