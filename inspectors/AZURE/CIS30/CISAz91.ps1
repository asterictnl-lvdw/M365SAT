# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Web App Redirects All HTTP traffic to HTTPS in Azure App Service
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
		FindingName	     = "CIS Az 9.1 - Some Azure Web Apps do not have HTTPS-only set to 'On'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Enabling HTTPS-only traffic will redirect all non-secure HTTP requests to HTTPS ports. HTTPS uses the TLS/SSL protocol to provide a secure connection which is both encrypted and authenticated. It is therefore important to support HTTPS for the security benefits."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Set-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> -HttpsOnly $true'
		DefaultValue	 = "HTTPS-only Feature is disabled"
		ExpectedValue    = "HTTPS-only Feature is enabled"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'HTTPS and Certificates'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/overview-security?source=recommendations#https-and-certificates' },
		@{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit' },
		@{ 'Name' = 'Enable HTTPS setting on Azure App service using Azure policy'; 'URL' = 'https://techcommunity.microsoft.com/t5/azure-paas-blog/enable-https-setting-on-azure-app-service-using-azure-policy/ba-p/3286603' })
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
			if ($WebApp.HttpsOnly -ne $true){
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