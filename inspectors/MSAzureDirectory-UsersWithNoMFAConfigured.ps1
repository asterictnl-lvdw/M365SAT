# This is an UsersWithNoMFAConfigured Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks the users that have no MFA Configured within the tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-UsersWithNoMFAConfigured($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0017"
		FindingName	     = "Users with No MFA Configured"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "9.3"
		Description	     = "The users listed above do not have at least one multi-factor authentication method (such as a phone or mobile app) configured. Note that this detector relies on reading settings configured within Microsoft Online/Azure AD and may not account for Conditional Access Policies."
		Remediation	     = "Educate users about mandatory MFA and its purpose. Consider using an MFA enrollment option that requires users to configure at least one MFA method upon their next login. Continue to monitor the status of MFA via 365Inspect, direct PowerShell commands, the Office 365 administration portal, or other appropriate tooling to assess whether users configure MFA over time."
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Set Up Multi-Factor Authentication'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/set-up-multi-factor-authentication?view=o365-worldwide" })
	}
}


function Inspect-UsersWithNoMFAConfigured
{
	Try
	{
		
		$conditionalAccess = Get-MgIdentityConditionalAccessPolicy
		
		$flag = $false
		
		Foreach ($policy in $conditionalAccess)
		{
			If (($policy.conditions.users.includeusers -eq "All") -and ($policy.grantcontrols.builtincontrols -like "Mfa"))
			{
				$flag = $true
			}
		}
		
		If (!$flag)
		{
			$unenabled_users = (Get-MsolUser -All | Where-Object { ($_.isLicensed -eq $true) -and ($_.StrongAuthenticationMethods.Count -eq 0) -and ($_.BlockCredential -eq $False) -and ($_.StrongAuthenticationRequirements.State -NE "Enforced") }).UserPrincipalName
			
			If ($unenabled_users -ne 0)
			{
				$endobject = Build-UsersWithNoMFAConfigured($unenabled_users)
				Return $endobject
			}
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
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname -failinglinenumber $failinglinenumber -failingline $failingline -pscommandpath $pscommandpath -positionmsg $pscommandpath -stacktrace $strace
		Write-Verbose "Errors written to log"
	}
	
}

return Inspect-UsersWithNoMFAConfigured


