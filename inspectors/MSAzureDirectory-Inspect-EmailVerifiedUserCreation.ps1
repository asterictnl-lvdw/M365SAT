# This is an EmailVerifiedUserCreation Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Users Accounts are created via Email Verified Self-Service Creation
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-EmailVerifiedUserCreation($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0013"
		FindingName	     = "User Accounts Created via Email Verified Self-Service Creation Found"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "8.5"
		Description	     = "Recently a blog was published about a method of tenant takeover using expired domain registrations. This method relied on a domain registration expiring and the domain remaining associated with the tenant. Monitoring account creation types can help detect and alert on attempts to exploit this attack path. Outlined in both Soteria's blog 'Azure AD Default Configuration Blunders' and the newly published 'LetItGo: A Case Study in Expired Domains and Azure AD' blog is the risk of allowing Microsoft's self-service sign-up for Azure Active Directory. Microsoft initially issued fixes for this attack between December 2021 and January 2022, but has since rolled back those efforts."
		Remediation	     = "Review any accounts returned to ensure they are appropriate for the tenant. Determine if the self-service sign-up configuration is appropriate for business needs and either remediate as outlined, or implement a continuous monitoring solution for accounts created via the self-service method."
		PowerShellScript = 'Set-MsolCompanySettings -AllowEmailVerifiedUsers $false -AllowAdHocSubscriptions $false'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'What is self-service sign-up for Azure Active Directory?'; 'URL' = "https://soteria.io/dnsense-online-brand-protection/" },
			@{ 'Name' = 'Azure AD Default Configuration Blunders'; 'URL' = "https://soteria.io/dnsense-online-brand-protection/" })
	}
}

Function Inspect-EmailVerifiedUserCreation
{
	Try
	{
		
		$emailVerifiedUsers = Get-MgUser -All:$true | Where-Object { $_.CreationType -eq "EmailVerified" }
		
		$results = @()
		
		$emailVerifiedUsers | Select-Object AccountEnabled, DisplayName, ShowInAddressList, UserPrincipalName, OtherMails | Format-Table -AutoSize | Out-File "$path\EmailVerifiedUserCreation.txt"
		
		foreach ($account in $emailVerifiedUsers)
		{
			$results += $account.UserPrincipalName
		}
		if ($results -ne $null)
		{
			$endobject = Build-EmailVerifiedUserCreation($results)
			Return $endobject
		}
		else
		{
			return $null
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

Return Inspect-EmailVerifiedUserCreation


