# This is an PasswordPolicyNoExpiration Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Office 365
# Purpose: Checks if the Password Expiration is set on No Expiration
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-PasswordPolicyNoExpiration($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMO3650003"
		FindingName	     = "Password Expiration Period is Set"
		ProductFamily    = "Microsoft Office 365"
		CVS			     = "0.0"
		Description	     = "O365 passwords are set to expire after an administrator-specified period of time. Although security controls like this may have been recommended in the past, in recent years many security standards bodies have begun to advocate against password expiration policies. Such policies violate the fundamental secure design principle of psychological acceptability--that is, if security mechanisms are overly intrusive and demanding to a user, users will simply seek to bypass or disable the security mechanism. In practice, it is sometimes observed that users select weaker, more repetitive, or more easily-guessed passwords when there is a password expiry period. They may also save passwords in an insecure file or physical location if they cannot remember them. It is therefore not recommended to have a password expiry period unless the passwords are changed transparently to the users, as with a password management solution."
		Remediation	     = "This setting can be changed from within the O365 Administration Center. Navigate to Settings -> Org Settings -> Security and Privacy -> Password Expiration Policy and uncheck the box. It can also be configured via PowerShell using the Set-MsolPasswordPolicy command as described in the references below."
		DefaultValue	 = "2147483647"
		ExpectedValue    = "2147483647"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		PowerShellScript = 'Set-MsolPasswordPolicy -ValidityPeriod 2147483647 -NotificationDays 0 -DomainName '+ $OrgName
		References	     = @(@{ 'Name' = 'Set the password expiration policy for your organization'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/admin/manage/set-password-expiration-policy?view=o365-worldwide' },
			@{ 'Name' = 'Set-MsolPasswordPolicy Reference'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/msonline/set-msolpasswordpolicy?view=azureadps-1.0' },
			@{ 'Name' = 'NIST: Password expiration no longer recommended'; 'URL' = 'https://pages.nist.gov/800-63-FAQ/#q-b05' })
	}
}

function Audit-PasswordPolicyNoExpiration
{
	try
	{
		$ppnoexpire = Get-MsolPasswordPolicy -DomainName "$org_name.onmicrosoft.com"
		if (-NOT $ppnoexpire.ValidityPeriod -eq 2147483647)
		{
			$endobject = Build-PasswordPolicyNoExpiration('ValidityPeriod: ' + $ppnoexpire.ValidityPeriod)
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
return Audit-PasswordPolicyNoExpiration