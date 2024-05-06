# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Sharepoint
# Purpose: Checks if Third-Party Applications are allowed
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-O365002($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-O365002"
		FindingName	     = "CSTM-O365002 - Third-Party Applications are Allowed"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "9"
		Description	     = "Third-party integrated applications are allowed to run in the organization's Office 365 environment if a user authorizes them to do so. This configuration is considered insecure because a user may grant permissions to a malicious application without fully understanding the security implications. A user who installs a malicious third-party application is in effect compromised. Additionally, there are documented cases of a malicious actor gaining access to sensitive information by enticing a user to allow a third-party integrated application to run within their O365 Tenant."
		Remediation	     = "In the Office 365 administration center, navigate to the Org Settings page, then select Services -> User Consent to Apps and turn user consent off."
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		PowerShellScript = 'Set-OrganizationConfig -EwsApplicationAccessPolicy EnforceBlockList; Set-OrganizationConfig -EwsBlockList @{add="LinkedInEWS*"}'
		References	     = @(@{ 'Name' = 'Understand subscriptions and licenses in Microsoft 365 for business'; 'URL' = 'https://docs.microsoft.com/en-us/microsoft-365/commerce/licenses/subscriptions-and-licenses?view=o365-worldwide' },
			@{ 'Name' = 'About Microsoft 365'; 'URL' = 'https://www.microsoft.com/en-us/licensing/product-licensing/microsoft-365' })
	}
}


function Inspect-CSTM-O365002
{
	Try
	{
		
		$permissions = (Get-MgPolicyAuthorizationPolicy).defaultuserrolepermissions
		
		If ($permissions.AllowedToCreateApps -eq $true)
		{
			$endobject = Build-CSTM-O365002($permissions.AllowedToCreateApps)
			Return $endobject
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-O365002


