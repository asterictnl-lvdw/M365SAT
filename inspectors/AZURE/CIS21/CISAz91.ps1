# Date: 25-1-2023091
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure App Service Authentication is set up for apps in Azure App Service
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz91($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz91"
		FindingName	     = "CIS Az 9.1 - App Service Authentication is not set up for apps in Azure App Service"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "By Enabling App Service Authentication, every incoming HTTP request passes through it before being handled by the application code. It also handles authentication of users with the specified provider (Entra ID, Facebook, Google, Microsoft Account, and Twitter), validation, storing and refreshing of tokens, managing the authenticated sessions and injecting identity information into request headers. Disabling HTTP Basic Authentication functionality further ensures legacy authentication methods are disabled within the application."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Set-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> -HttpsOnly $true -Enabled $true'
		DefaultValue	 = "By default, App Service Authentication is disabled"
		ExpectedValue    = "App Service Authentication is enabled"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Authentication and authorization in Azure App Service and Azure Functions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/overview-authentication-authorization' })
	}
	return $inspectorobject
}

function Audit-CISAz91
{
	try
	{
		
		$Violation = @()
		$WebApps = Get-AzWebApp -ProgressAction SilentlyContinue
		foreach ($WebApp in $WebApps){
			$App = Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue
			if ($App.Enabled -ne $true){
				$Violation += $WebApp.DefaultHostName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz91($Violation)
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
return Audit-CISAz91