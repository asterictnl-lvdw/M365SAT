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


function Build-CISMOff134($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff134"
		FindingName	     = "CIS MOff 1.3.4 - User owned apps and services are not restricted"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "15"
		Description	     = "Attackers commonly use vulnerable and custom-built add-ins to access data in user applications. While allowing users to install add-ins by themselves does allow them to easily acquire useful add-ins that integrate with Microsoft applications, it can represent a risk if not used and monitored carefully. Disable future user's ability to install add-ins in Microsoft Word, Excel, or PowerPoint helps reduce your threat-surface and mitigate this risk."
		Remediation	     = "Manually uncheck at User owned apps and services the first two options so all 3 checkboxes are unchecked."
		PowerShellScript = 'https://admin.microsoft.com/Adminportal/Home#/Settings/Services/:/Settings/L1/Store'
		DefaultValue	 = "iwpurchaseallowed: True / iwpurchasefeatureenabled: True"
		ExpectedValue    = "iwpurchaseallowed: False / iwpurchasefeatureenabled: False"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Microsoft Admin Portal'; 'URL' = 'https://admin.microsoft.com/' })
	}
	return $inspectorobject
}

function Audit-CISMOff134
{
	try
	{
		$AffectedSettings = @()
		# Actual Script
		$AccessStoreSetting = Invoke-MultiMicrosoftAPI -Url "https://admin.microsoft.com/admin/api/storesettings/iwpurchaseallowed" -Resource "https://admin.microsoft.com" -Method 'GET'
		$StartTrialsSetting = Invoke-MultiMicrosoftAPI -Url "https://admin.microsoft.com/admin/api/storesettings/iwpurchasefeatureenabled" -Resource "https://admin.microsoft.com" -Method 'GET'
		
		# Validation
		if ($AccessStoreSetting -eq $true)
		{
			$AffectedSettings += "iwpurchaseallowed: $($AccessStoreSetting)"
		}
		if ($StartTrialsSetting -eq $true)
		{
			$AffectedSettings += "iwpurchasefeatureenabled: $($StartTrialsSetting)"
		}
		if ($AffectedSettings.Count -igt 0)
		{
			$AffectedSettings | Format-Table -AutoSize | Out-File "$path\CISMOff134-iwpurchaseSettings.txt" 
			$finalobject = Build-CISMOff134($AffectedSettings)
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
return Audit-CISMOff134