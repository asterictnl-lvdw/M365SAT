# This is an UsersWithNoMFAEnforced Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks the users that have no MFA Enforces within the tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-UsersWithNoMFAEnforced($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0018"
		FindingName	     = "Users with No Multi-Factor Authentication Enforced"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "9.3"
		Description	     = "The Microsoft Azure / Microsoft 365 user accounts listed above do not have multi-factor authentication enforced by an administrator. Multi-factor authentication is an essential security setting that can prevent an adversary from compromising a user account even if the adversary has their password. Multi-factor authentication is an additional obstacle to adversaries who obtain user credentials through phishing or other means. Note that this module relies on reading settings configured within Microsoft Online/Azure AD and may not account for Conditional Access Policies or the use of third-party MFA solutions."
		Remediation	     = "There are multiple different ways to roll out MFA and several considerations to take into account before rolling out MFA to the organization. Multi-factor authentication rollout can require significant effort. Follow the detailed O365 MFA guide in references"
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "All user accounts"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Set Up Multi-Factor Authentication'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/set-up-multi-factor-authentication?view=o365-worldwide" })
	}
}

function Inspect-UsersWithNoMFAEnforced
{
	Try
	{
		
		# Query Security defaults to see if it's enabled. If it is, skip this check.
		$secureDefault = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -Property IsEnabled | Select-Object IsEnabled
		If ($secureDefault.IsEnabled -eq $false)
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
				$unenforced_users = (Get-MsolUserByStrongAuthentication -MaxResults 999999 | Where-Object { ($_.isLicensed -eq $true) -and ($_.StrongAuthenticationRequirements.State -NE "Enforced") }).UserPrincipalName
				$num_unenforced_users = $unenforced_users.Count
				If ($num_unenforced_users -NE 0)
				{
					$endobject = Build-UsersWithNoMFAEnforced($unenforced_users)
					Return $endobject
				}
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

return Inspect-UsersWithNoMFAEnforced


