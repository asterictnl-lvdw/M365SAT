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


function Build-CSTM-Az010($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az010"
		FindingName	     = "CSTM-Az010 - OnPremisesPasswordResetPolicies does not have the correct security settings configured"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Azure Active Directory (Azure AD) self-service password reset (SSPR) lets users reset their passwords in the cloud, but most companies also have an on-premises Active Directory Domain Services (AD DS) environment for users. Password writeback allows password changes in the cloud to be written back to an on-premises directory in real time by using either Azure AD Connect or Azure AD Connect cloud sync. When users change or reset their passwords using SSPR in the cloud, the updated passwords also written back to the on-premises AD DS environment."
		Remediation	     = "Manually check the boxes by navigating to the link displayed in PowerShellScript."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/OnPremisesIntegration/fromNav/Identity'
		DefaultValue	 = "accountUnlockEnabled: false / accountUnlockSupported: true / cloudProvisioningEnablementForTenant: false / enablementForTenant: true / passwordWritebackSupported: true"
		ExpectedValue    = "accountUnlockEnabled: true / accountUnlockSupported: true / cloudProvisioningEnablementForTenant: true / enablementForTenant: true / passwordWritebackSupported: true"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'How does self-service password reset writeback work in Azure Active Directory?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-sspr-writeback' })
	}
	return $inspectorobject
}

function Audit-CSTM-Az010
{
	try
	{
		# Actual Script
		$OnPremIntegrationProtection = @()
		$OnPremIntegration = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/PasswordReset/OnPremisesPasswordResetPolicies' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		if ($OnPremIntegration.accountUnlockEnabled -ne $true)
		{
			$OnPremIntegrationProtection += "accountUnlockEnabled: $($OnPremIntegration.accountUnlockEnabled)"
		}
		
		if ($OnPremIntegration.accountUnlockSupported -ne $true)
		{
			$OnPremIntegrationProtection += "accountUnlockSupported: $($OnPremIntegration.accountUnlockSupported)"
		}
		
		if ($OnPremIntegration.cloudProvisioningEnablementForTenant -ne $true)
		{
			$OnPremIntegrationProtection += "cloudProvisioningEnablementForTenant: $($OnPremIntegration.cloudProvisioningEnablementForTenant)"
		}
		
		if ($OnPremIntegration.enablementForTenant -ne $true)
		{
			$OnPremIntegrationProtection += "enablementForTenant: $($OnPremIntegration.enablementForTenant)"
		}
		
		if ($OnPremIntegration.passwordWritebackSupported -ne $true)
		{
			$OnPremIntegrationProtection += "passwordWritebackSupported: $($OnPremIntegration.passwordWritebackSupported)"
		}
		
		# Validation
		if ($OnPremIntegrationProtection.Count -igt 0)
		{
			$finalobject = Build-CSTM-Az010($OnPremIntegrationProtection)
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
return Audit-CSTM-Az010