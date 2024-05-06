#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Sways cannot be shared with people outside of your organization
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMOff2110($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff2110"
		FindingName	     = "CIS MOff 2.11 - Sways can be shared with people outside of your organization"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "3"
		Description	     = "Disable external sharing of Sway documents that can contain sensitive information to prevent accidental or arbitrary data leak."
		Remediation	     = "Manually uncheck at Sway Setting in the Admin Portal. The respective setting: 'Let people in your organization share their sways with people outside your organization'"
		PowerShellScript = 'https://admin.microsoft.com/Adminportal/Home#/Settings/Services/:/Settings/L1/Sway'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Administrator settings for Microsoft Forms'; 'URL' = 'https://learn.microsoft.com/en-US/microsoft-forms/administrator-settings-microsoft-forms' },
			@{ 'Name' = 'Review and unblock forms or users detected and blocked for potential phishing'; 'URL' = 'https://learn.microsoft.com/en-US/microsoft-forms/review-unblock-forms-users-detected-blocked-potential-phishing' })
	}
	return $inspectorobject
}

function Audit-CISMOff2110
{
	try
	{
		$AffectedSettings = @()
		# Actual Script
		$Response = Invoke-MultiMicrosoftAPI -Url "https://admin.microsoft.com/admin/api/settings/apps/Sway" -Resource "https://admin.microsoft.com" -Method 'GET'
		
		# Validation
		if ($SwaySetting.ExternalSharingEnabled -eq $true)
		{
			$AffectedSettings += "ExternalSharingEnabled: $($SwaySetting.ExternalSharingEnabled)"
		}
		if ($AffectedSettings.Count -igt 0)
		{
			$finalobject = Build-CISMOff2110($AffectedSettings)
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
return Audit-CISMOff2110