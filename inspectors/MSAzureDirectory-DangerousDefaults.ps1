# This is an DangerousDefaults Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if DangerousDefault Settings are enabled within the Azure Tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-DangerousDefaults($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0006"
		FindingName	     = "Azure Contains Dangerous Default Permissions"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "9.3"
		Description	     = "Dangerous default configuration settings were found in the tenant. By default, Azure tenants allow all users to access the Azure Active Directory blade, to read all other users' accounts, create groups, and invite guests. These default settings extend to guest accounts as well, allowing guests to perform these same actions. Other default configurations allow for Self-Service creation of accounts from accepted mail domains."
		Remediation	     = "If False was returned, consider creating Conditional Access policies or re-enabling Secure Defaults. For recommended configuration, please use the references to configure Conditional Access Policies within your Azure Tenant."
		PowerShellScript = 'Set-MsolCompanySettings -UsersPermissionToReadOtherUsersEnabled $false; Set-MsolCompanySettings -UsersPermissionToCreateGroupsEnabled $false; Set-AzureADMSAuthorizationPolicy -id (Get-AzureADMSAuthorizationPolicy).id -AllowEmailVerifiedUsersToJoinOrganization $false'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'Directory Self Service Signup'; 'URL' = "https://techcommunity.microsoft.com/t5/azure-active-directory-identity/raising-the-baseline-security-for-all-organizations-in-the-world/ba-p/3299048" },
			@{ 'Name' = 'Limit User Access'; 'URL' = "https://helloitsliam.com/2021/09/23/create-conditional-access-policies-using-powershell/" },
			@{ 'Name' = 'Azure AD - Attack of the Default Config'; 'URL' = "https://www.pentestpartners.com/security-blog/azure-ad-attack-of-the-default-config/" },
			@{ 'Name' = 'Azure AD Default Configuration Blunders'; 'URL' = "https://medium.com/soteria-security/azure-ad-default-configuration-blunders-c7abddeae56" })
	}
}


function Inspect-DangerousDefaults
{
	Try
	{
		
		$permissions = (Get-MgPolicyAuthorizationPolicy).defaultuserrolepermissions
		$authPolicy = Get-MgPolicyAuthorizationPolicy
		
		$dangerousDefaults = @()
		
		
		If ($permissions.AllowedToReadOtherUsers -eq $true)
		{
			$dangerousDefaults += "Users can read all attributes in Azure AD"
		}
		if ($permissions.AllowedToCreateSecurityGroups -eq $true)
		{
			$dangerousDefaults += "Users can create security groups"
		}
		if ($permissions.AllowedToCreateApps -eq $true)
		{
			$dangerousDefaults += "Users are allowed to create and register applications"
		}
		if ($authPolicy.AllowEmailVerifiedUsersToJoinOrganization -eq $true)
		{
			$dangerousDefaults += "Users with a verified mail domain can join the tenant"
		}
		if ($authPolicy.AllowInvitesFrom -like "everyone")
		{
			$dangerousDefaults += "Guests can invite other guests into the tenant"
		}
		
		If ($dangerousDefaults.count -ne 0)
		{
			$endobject = Build-DangerousDefaults($dangerousDefaults)
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

return Inspect-DangerousDefaults


