# This is an ThirdPartyIntegratedAppPermission Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Office 365
# Purpose: Checks te Third-Party Applications Allowance within your tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-ThirdPartyIntegratedAppPermission($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMO3650006"
		FindingName	     = "Third-Party Applications Allowed"
		ProductFamily    = "Microsoft Office 365"
		CVS			     = "9.6"
		Description	     = "Third-party integrated applications are allowed to run in the organization's Office 365 environment if a user authorizes them to do so. This configuration is considered insecure because a user may grant permissions to a malicious application without fully understanding the security implications. A user who installs a malicious third-party application is in effect compromised. Additionally, there are documented cases of a malicious actor gaining access to sensitive information by enticing a user to allow a third-party integrated application to run within their O365 Tenant."
		Remediation	     = "In the Office 365 administration center, navigate to the Org Settings page, then select Services -> User Consent to Apps and turn user consent off."
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		PowerShellScript = 'Set-OrganizationConfig -EwsApplicationAccessPolicy EnforceBlockList; Set-OrganizationConfig -EwsBlockList @{add="LinkedInEWS*"}'
		References	     = @(@{ 'Name' = 'Understand subscriptions and licenses in Microsoft 365 for business'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/commerce/licenses/subscriptions-and-licenses?view=o365-worldwide' },
			@{ 'Name' = 'About Microsoft 365'; 'URL' = 'https://www.microsoft.com/en-us/licensing/product-licensing/microsoft-365' })
	}
}


function Inspect-ThirdPartyIntegratedAppPermission
{
	Try
	{
		
		$permissions = (Get-MgPolicyAuthorizationPolicy).defaultuserrolepermissions
		
		If ($permissions.AllowedToCreateApps -eq $true)
		{
			$endobject = Build-ThirdPartyIntegratedAppPermission($permissions.AllowedToCreateApps)
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
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname -failinglinenumber $failinglinenumber -failingline $failingline -pscommandpath $pscommandpath -positionmsg $pscommandpath -stacktrace $strace
		Write-Verbose "Errors written to log"
	}
	
}

return Inspect-ThirdPartyIntegratedAppPermission


