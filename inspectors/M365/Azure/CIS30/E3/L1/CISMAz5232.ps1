#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Checks if a banned password list is used
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5232($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5232"
		FindingName	     = "CISM MAz 5.2.3.2 - No Custom Bad Password List is used within your organization"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Creating a new password can be difficult regardless of one's technical background. It is common to look around one's environment for suggestions when building a password, however, this may include picking words specific to the organization as inspiration for a password. An adversary may employ what is called a 'mangler' to create permutations of these specific words in an attempt to crack passwords or hashes making it easier to reach their goal."
		Remediation	     = "Manually enable Enforce custom list and set it to True. There is no script available at this moment unfortunately."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection'
		DefaultValue	 = "False + No List"
		ExpectedValue    = "True + List with passwords"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Tutorial: Configure custom banned passwords for Microsoft Entra password protection'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-configure-custom-password-protection' },
			@{ 'Name' = 'Eliminate bad passwords using Microsoft Entra Password Protection'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad#custom-banned-password-list' })
	}
	return $inspectorobject
}

function Audit-CISMAz5232
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
			$AffectedOptions | Format-Table -AutoSize | Out-File "$path\CISMAz5232-PasswordPolicy.txt"
			$finalobject = Build-CISMAz5232($AffectedOptions)
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

return Audit-CISMAz5232