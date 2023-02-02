# This is an SelfServePasswordReset Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if SelfServePasswordReset is enabled within Azure Tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SelfServePasswordReset($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0016"
		FindingName	     = "Self-Serve Password Reset is Not Enabled"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "7.7"
		Description	     = "Office 365's Self-Serve Password Reset feature enables users to reset their own password. It is recommended to allow users to reset their own passwords for the purpose of recovering their account in the event of accidental lockout or a security incident."
		Remediation	     = "This setting can be changed in the O365 Administration center, under Settings -> Org Settings -> Security & Privacy. A detailed guide is provided in the references section below."
		PowerShellScript = 'Set-MsolCompanySettings -SelfServePasswordResetEnabled $True'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'What are security defaults?'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults" })
	}
}


function Inspect-SelfServePasswordReset
{
	Try
	{
		
		$self_serve_reset_enabled = (Get-MgPolicyAuthorizationPolicy).AllowedToUseSspr
		
		If (-NOT $self_serve_reset_enabled)
		{
			$endobject = Build-SelfServePasswordReset($self_serve_reset_enabled)
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

return Inspect-SelfServePasswordReset


