#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft 365
# Purpose: Ensure 'User owned apps and services' is restricted
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMOff137($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff137"
		FindingName	     = "CIS MOff 1.3.7 - 'third-party storage services' are not restricted in 'Microsoft 365 on the web'"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "15"
		Description	     = "By using external storage services an organization may increases the risk of data breaches and unauthorized access to confidential information. Additionally, third-party services may not adhere to the same security standards as the organization, making it difficult to maintain data privacy and security."
		Remediation	     = "Manually uncheck the box 'Let users open files stored in third-party storage services in Microsoft 365 on the web'. The URL is given in PowerShellScript."
		PowerShellScript = 'https://admin.microsoft.com/Adminportal/Home#/Settings/Services/:/Settings/L1/OfficeOnline'
		DefaultValue	 = "Enabled: True"
		ExpectedValue    = "Enabled: False"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Enable or disable third-party storage services'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/admin/setup/set-up-file-storage-and-sharing?view=o365-worldwide#enable-or-disable-third-party-storage-services' })
	}
	return $inspectorobject
}

function Audit-CISMOff137
{
	try
	{
		$AffectedSettings = @()
		# Actual Script
		$Office365WebSettings = Invoke-MultiMicrosoftAPI -Url "https://admin.microsoft.com/admin/api/settings/apps/officeonline" -Resource "https://admin.microsoft.com" -Method 'GET'
		
		# Validation
		if ($Office365WebSettings.Enabled -eq $true)
		{
			$AffectedSettings += "Enabled: $($Office365WebSettings.Enabled)"
		}
		if ($AffectedSettings.Count -igt 0)
		{
			$Office365WebSettings | Format-Table -AutoSize | Out-File "$path\CISMOff137-Office365WebSettings.txt"
			$finalobject = Build-CISMOff137($AffectedSettings)
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
return Audit-CISMOff137