#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: Checks if 'Number of methods required to reset' is set to '2'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az011($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az011"
		FindingName	     = "CSTM-Az011 - Account Lockout Protection not optimally configured"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "7.3"
		Description	     = "MFA fraud alerts are used to alert the admins when the multi-factor authentication request is initiated without the users' concern. In MFA fraud alerting, the users notify the admins by reporting fraudulent activity that occurred in their accounts."
		Remediation	     = "Manually enable the checkboxes to enable Account Lockout Protection and FraudAlerts for your organization"
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/MultifactorAuthenticationMenuBlade/~/AccountLockout/fromProviders~/false'
		DefaultValue	 = "accountLockoutDurationMinutes:5/accountLockoutResetMinutes:1/accountLockoutThreshold:5/blockForFraud:False/enableFraudAlert:False/fraudCode:null/defaultBypassTimespan:300/pinAttempts:null/smstimeoutseconds:null"
		ExpectedValue    = "accountLockoutDurationMinutes:5/accountLockoutResetMinutes:1/accountLockoutThreshold:5/blockForFraud:False/enableFraudAlert:True/fraudCode:0/defaultBypassTimespan:300/pinAttempts:3/smstimeoutseconds:300"
		ReturnedValue    = "$findings"
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		References	     = @(@{ 'Name' = 'Configure MFA Fraud Alerts in Azure AD : An Alarm for Security Emergency'; 'URL' = 'https://o365reports.com/2023/03/14/configure-mfa-fraud-alerts-in-azure-ad-an-alarm-for-security-emergency/' })
	}
	return $inspectorobject
}

function Audit-CSTM-Az011
{
	try
	{
		# Actual Script
		$MFALockoutSettings = @()
		$MultiFactorAuthLockoutSettings = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/MultiFactorAuthentication/GetOrCreateExpandedTenantModel' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		if ($MultiFactorAuthLockoutSettings.accountLockoutDurationMinutes -ilt 5)
		{
			$MFALockoutSettings += "accountLockoutDurationMinutes: $($MultiFactorAuthLockoutSettings.accountLockoutDurationMinutes)"
		}
		
		if ($MultiFactorAuthLockoutSettings.accountLockoutResetMinutes -igt 5)
		{
			$MFALockoutSettings += "accountLockoutResetMinutes: $($MultiFactorAuthLockoutSettings.accountLockoutResetMinutes)"
		}
		
		if ($MultiFactorAuthLockoutSettings.accountLockoutThreshold -igt 5)
		{
			$MFALockoutSettings += "accountLockoutThreshold: $($MultiFactorAuthLockoutSettings.accountLockoutThreshold)"
		}
		
		if ($MultiFactorAuthLockoutSettings.blockForFraud -ne $false)
		{
			$MFALockoutSettings += "blockForFraud: $($MultiFactorAuthLockoutSettings.blockForFraud)"
		}
		
		if ($MultiFactorAuthLockoutSettings.enableFraudAlert -ne $true)
		{
			$MFALockoutSettings += "enableFraudAlert: $($MultiFactorAuthLockoutSettings.enableFraudAlert)"
		}
		
		if ($MultiFactorAuthLockoutSettings.fraudCode -ne 0)
		{
			$MFALockoutSettings += "fraudCode: $($MultiFactorAuthLockoutSettings.fraudCode)"
		}
		
		if ([string]::IsNullOrEmpty($MultiFactorAuthLockoutSettings.fraudNotificationEmailAddresses))
		{
			$MFALockoutSettings += "There are no fraudNotificationEmailAddresses"
		}
		
		if ($MultiFactorAuthLockoutSettings.pinAttempts -igt 5)
		{
			$MFALockoutSettings += "pinAttempts: $($MultiFactorAuthLockoutSettings.pinAttempts)"
		}
		
		if ($MultiFactorAuthLockoutSettings.smsTimeoutSeconds -ilt 30)
		{
			$MFALockoutSettings += "smsTimeoutSeconds: $($MultiFactorAuthLockoutSettings.smsTimeoutSeconds)"
		}
		
		if ($MultiFactorAuthLockoutSettings.defaultBypassTimespan -igt 300)
		{
			$MFALockoutSettings += "defaultBypassTimespan: $($MultiFactorAuthLockoutSettings.defaultBypassTimespan)"
		}
		
		# Validation
		if ($MFALockoutSettings.Count -igt 0)
		{
			$finalobject = Build-CSTM-Az011($MFALockoutSettings)
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
return Audit-CSTM-Az011