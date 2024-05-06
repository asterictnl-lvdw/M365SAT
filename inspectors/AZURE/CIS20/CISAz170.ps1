#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Checks if 'Number of methods required to reset' is set to '2'
# Author: Leonardo van de Weteringh
# This control also applies to CIS Microsoft 365 MAz 1.1.10 - Ensure password protection is enabled for on-prem Active Directory

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz170($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz170"
		FindingName	     = "CIS Az 1.7 - No Custom Bad Password List is set to 'Enforce' for your Organization"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Enabling a Custom Bad Password List gives your organization further customization on what secure passwords are allowed. Setting a bad password list enables your organization to fine-tune its password policy further, depending on your needs. Removing easy-to-guess passwords increases the security of access to your Azure resources. This control also checks on CIS Microsoft 365 1.1.10 which is for OnPremise Checks"
		Remediation	     = "Manually enable Enforce custom list and set it to True. There is no script available at this moment unfortunately."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection'
		DefaultValue	 = "False + No List"
		ExpectedValue    = "True + List with passwords"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Combined password policy and check for weak passwords in Azure Active Directory'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad-combined-policy' },
			@{ 'Name' = 'Eliminate bad passwords using Azure Active Directory Password Protection'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-password-ban-bad' },
			@{ 'Name' = 'AzureAD PowerShell Module'; 'URL' = 'https://learn.microsoft.com/en-us/powershell/module/Azuread/?view=azureadps-2.0' },
			@{ 'Name' = 'Password Guidance'; 'URL' = 'https://www.microsoft.com/en-us/research/publication/password-guidance/' },
			@{ 'Name' = 'Tutorial: Configure custom banned passwords for Azure Active Directory password protection'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-configure-custom-password-protection' },
			@{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' })
	}
	return $inspectorobject
}

function Audit-CISAz170
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$MethodsRequired = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/AuthenticationMethods/PasswordPolicy' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		# Validation
		if ($MethodsRequired.enforceCustomBannedPasswords -eq $false)
		{
			$AffectedOptions += "CustomBannedPasswords: $($MethodsRequired.enforceCustomBannedPasswords)"
		}
		if ($MethodsRequired.bannedPasswordCheckOnPremisesMode -eq 0)
		{
			$AffectedOptions += "PolicyMode: $($MethodsRequired.bannedPasswordCheckOnPremisesMode)"
		}
		if ($MethodsRequired.customBannedPasswords.count -ilt 0)
		{
			$AffectedOptions += "Number of Bad Passwords Listed: $($MethodsRequired.customBannedPasswords.count)"
		}
		if ($MethodsRequired.enableBannedPasswordCheckOnPremises -eq $false)
		{
			$AffectedOptions += "Password protection for Windows Server Active Directory: $($MethodsRequired.enableBannedPasswordCheckOnPremises)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$finalobject = Build-CISAz170($AffectedOptions)
			return $finalobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}

function Invoke-MultiMicrosoftAPI
{
	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
		#The Name of the Resource
		[Parameter()]
		[String]$Resource,
		[Parameter()]
		#Body if a POST or PUT
		[Object]$Body,
		[Parameter()]
		#Specify the HTTP Method you wish to use. Defaults to GET
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)
	
	try
	{
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	catch
	{
		Connect-AzAccount -ErrorAction Stop
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	
	#Specify Resource
	$apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $Resource)
	
	# Creating the important header
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $apiToken.AccessToken.ToString()
		'Content-Type'  = 'application/json'
		'X-Requested-With' = 'XMLHttpRequest'
		'x-ms-client-request-id' = [guid]::NewGuid()
		'x-ms-correlation-id' = [guid]::NewGuid()
	}
	# URL Where PUT Request is being done. You can extract this from F12 
	
	$method = 'GET'
	
	#In Case your Method is PUT or POST to edit something. Change things here
	
	if ($method -eq 'PUT')
	{
		# Remediation Scripts HERE
		$contentpart1 = '{"restrictNonAdminUsers":false}'
		
		#Convert the content (DUMMY)
		$Body = $contentpart1
		
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'POST')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'GET')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -ErrorAction Stop
	}
	return $Response
}

return Audit-CISAz170