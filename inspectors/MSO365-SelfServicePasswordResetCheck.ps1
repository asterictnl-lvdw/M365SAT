# This is an SelfServicePasswordResetCheck Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Office 365
# Purpose: Checks if the SelfServicePasswordReset Function is enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SelfServicePasswordResetCheck($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMO3650004"
		FindingName	     = "Self-Service Password Reset Not Active!"
		ProductFamily    = "Microsoft Office 365"
		CVS			     = "0.0"
		Description	     = "Enabling self-service password reset allows users to reset their own passwords in Azure AD. When your users sign in to Microsoft 365, they will be prompted to enter additional contact information that will help them reset their password in the future."
		Remediation	     = "Run the PowerShell script to remediate this issue."
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		PowerShellScript = 'Set-MsolCompanySettings -SelfServePasswordResetEnabled $True'
		References	     = @(@{ 'Name' = 'Enable combined security information registration in Azure Active Directory'; 'URL' = 'https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-registration-mfa-sspr-combined' },
			@{ 'Name' = 'Let users reset their own passwords'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/let-users-reset-passwords?redirectSourcePath=%252fen-us%252farticle%252flet-users-reset-their-own-passwords-in-office-365-5bc3f460-13cc-48c0-abd6-b80bae72d04a&view=o365-worldwide' })
	}
}

function Audit-SelfServicePasswordResetCheck
{
	try
	{
		$selfservicepswdreset = Get-MsolCompanyInformation | Select SelfServePasswordResetEnabled
		if ($selfservicepswdreset.SelfServePasswordResetEnabled -match 'False')
		{
			$endobject = Build-SelfServicePasswordResetCheck('SelfServePasswordResetEnabled: ' + $selfservicepswdreset.SelfServePasswordResetEnabled)
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
return Audit-SelfServicePasswordResetCheck