#Applies to CIS and the URL https://soteria.io/azure-ad-default-configuration-blunders/ for extra audit material!
# This is an DURPAZAPP Inspector.

# Date: 23-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if DefaultUserRolePermissions for Azure Apps are correctly configured
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-DURPAZAPP($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0007"
		FindingName	     = "Role Permissions are not set conform CIS Standards. Some values returned True, instead of False."
		ProductFamily    = "Microsoft Azure"
		CVS			     = "8.5"
		Description	     = "All property values should be False instead of True: AllowedToCreateApps,AllowedToCreateSecurityGroups,AllowedToReadOtherUsers,AllowedToSignUpEmailBasedSubscriptions,AllowEmailVerifiedUsersToJoinOrganization. If one of the values is True this could lead to: 1. A standard user gaining sensitive information about other users 2. Users creating groups with possible elevated privileges, 3. Creating possible Malicious apps without restrictions."
		Remediation	     = "Based on the values of Affected Objects use the PowerShell script to mitigate this issue."
		PowerShellScript = 'Set-MsolCompanySettings -UsersPermissionToReadOtherUsersEnabled $false and Set-MsolCompanySettings -UsersPermissionToCreateGroupsEnabled $false and Set-MsolCompanySettings -UsersPermissionToUserConsentToAppEnabled $false; Set-AzureADMSAuthorizationPolicy -DefaultUserRolePermissions @{"PermissionGrantPoliciesAssigned" = @(); "AllowedToCreateApps" = $false; "AllowedToCreateSecurityGroups" = $false; "AllowedToReadOtherUsers" = $false }'
		DefaultValue	 = "AllowedToCreateApps: True <br /> AllowedToCreateSecurityGroups: True <br /> AllowedToReadOtherUsers: True <br /> AllowedToSignUpEmailBasedSubscriptions: True <br /> AllowEmailVerifiedUsersToJoinOrganization: True <br /> "
		ExpectedValue    = "AllowedToCreateApps: False <br /> AllowedToCreateSecurityGroups: False <br /> AllowedToReadOtherUsers: False <br /> AllowedToSignUpEmailBasedSubscriptions: False <br /> AllowEmailVerifiedUsersToJoinOrganization: False <br /> "
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Detect when compromised end-user connects to Azure-AD for reconnaissance'; 'URL' = "https://m365security.net/2021/04/05/detect-when-compromised-end-user-connects-to-azure-ad-for-reconnaissance/" },
			@{ 'Name' = 'Azure AD - Attack of the Default Config'; 'URL' = "https://www.pentestpartners.com/security-blog/azure-ad-attack-of-the-default-config/" },
			@{ 'Name' = 'Azure AD Default Configuration Blunders'; 'URL' = "https://medium.com/soteria-security/azure-ad-default-configuration-blunders-c7abddeae56" })
	}
}

$ErrorActionPreference = "Stop"

$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

. $errorHandling

function Audit-DURPAZAPP
{
	try
	{
		$DURPAZAAPP = @()
		$DURPAZAPPT1 = Get-AzureADMSAuthorizationPolicy | select AllowedToSignUpEmailBasedSubscriptions, AllowEmailVerifiedUsersToJoinOrganization -ExpandProperty DefaultUserRolePermissions -ExcludeProperty PermissionGrantPoliciesAssigned
		$DURPAZAPPT2 = Get-MsolCompanyInformation | select UsersPermissionToReadOtherUsersEnabled, UsersPermissionToCreateGroupsEnabled, UsersPermissionToUserConsentToAppEnabled
		if ($DURPAZAPPT1.AllowedToCreateApps -match 'True' -or $DURPAZAPPT1.AllowedToCreateSecurityGroups -match 'True' -or $DURPAZAPPT1.AllowedToReadOtherUsers -match 'True' -or $DURPAZAPPT1.AllowedToSignUpEmailBasedSubscriptions -match 'True' -or $DURPAZAPPT1.AllowEmailVerifiedUsersToJoinOrganization -match 'True')
		{
			$DURPAZAAPP += " AllowedToCreateApps: " + $DURPAZAPPT1.AllowedToCreateApps
			$DURPAZAAPP += "`n AllowedToCreateSecurityGroups: " + $DURPAZAPPT1.AllowedToCreateSecurityGroups
			$DURPAZAAPP += "`n AllowedToReadOtherUsers: " + $DURPAZAPPT1.AllowedToReadOtherUsers
			$DURPAZAAPP += "`n AllowedToSignUpEmailBasedSubscriptions: " + $DURPAZAPPT1.AllowedToSignUpEmailBasedSubscriptions
			$DURPAZAAPP += "`n AllowEmailVerifiedUsersToJoinOrganization: " + $DURPAZAPPT1.AllowEmailVerifiedUsersToJoinOrganization
		}
		if ($DURPAZAPPT2.UsersPermissionToReadOtherUsersEnabled -match 'True' -or $DURPAZAPPT2.UsersPermissionToCreateGroupsEnabled -match 'True' -or $DURPAZAPPT2.UsersPermissionToUserConsentToAppEnabled -match 'True')
		{
			foreach ($DURPAZAPPT2DataObj in $DURPAZAPPT2)
			{
				$DURPAZAAPP += " UsersPermissionToReadOtherUsersEnabled: " + $DURPAZAPPT2.UsersPermissionToReadOtherUsersEnabled
				$DURPAZAAPP += "`n UsersPermissionToCreateGroupsEnabled: " + $DURPAZAPPT2.UsersPermissionToCreateGroupsEnabled
				$DURPAZAAPP += "`n UsersPermissionToUserConsentToAppEnabled: " + $DURPAZAPPT2.UsersPermissionToUserConsentToAppEnabled
			}
		}
		If ($DURPAZAAPP.count -ne 0)
		{
			$endobject = Build-DURPAZAPP($DURPAZAAPP)
			Return $endobject
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
return Audit-DURPAZAPP