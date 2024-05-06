#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Checks if 'Number of methods required to reset' is set to '2'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz118($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz118"
		FindingName	     = "CISM Az 1.1.8 - Self Service Password Reset is not set to be enabled for all users"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "9"
		Description	     = "Users will no longer need to engage the helpdesk for password resets, and the password reset mechanism will automatically block common, easily guessable passwords."
		Remediation	     = "Manually change the value from 0 (None) or 1 (Selected) to 2 (All) in the Azure Portal. There is no script available at this moment unfortunately."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/Properties'
		DefaultValue	 = "0"
		ExpectedValue    = "2"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Tutorial: Enable users to unlock their account or reset passwords using Azure Active Directory self-service password reset'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/tutorial-enable-sspr' },
			@{ 'Name' = 'Combined security information registration for Azure Active Directory overview'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-registration-mfa-sspr-combined' },
			@{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' },
			@{ 'Name' = 'Password reset registration'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/active-directory-passwords-faq#password-reset-registration' },
			@{ 'Name' = 'Plan an Azure Active Directory self-service password reset deployment'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/howto-sspr-deployment' },
			@{ 'Name' = 'What authentication and verification methods are available in Azure Active Directory?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-authentication-methods' })
	}
	return $inspectorobject
}

function Audit-CISMAz118
{
	try
	{
		# Actual Script
		$SSPRSetting = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=true' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		# Validation
		if ($SSPRSetting.enablementType -ne 2)
		{
			$finalobject = Build-CISMAz118($SSPRSetting.enablementType)
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
return Audit-CISMAz118