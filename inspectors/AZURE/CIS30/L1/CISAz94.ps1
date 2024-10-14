# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Web App is using the latest version of TLS encryption
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz94($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz94"
		FindingName	     = "CIS Az 9.4 - Web App is not using the latest version of TLS encryption"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app secure connections."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Set-AzWebApp -ResourceGroupName <RESOURCE_GROUP_NAME> -Name <APP_NAME> -MinTlsVersion 1.2'
		DefaultValue	 = "1.2"
		ExpectedValue    = "1.2"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Provide security for a custom DNS name with a TLS/SSL binding in App Service'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-tls-versions' },
		@{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit' },
		@{ 'Name' = 'NS-8: Detect and disable insecure services and protocols'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-8-detect-and-disable-insecure-services-and-protocols' })
	}
	return $inspectorobject
}

function Audit-CISAz94
{
	try
	{
		$Violation = @()
		$WebApps = Get-AzWebApp -ProgressAction SilentlyContinue
		foreach ($WebApp in $WebApps){
			$App = (Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue).SiteConfig.MinTlsVersion
			if ($App -ne "1.2"){
				$Violation += $WebApp.DefaultHostName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz94($Violation)
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
return Audit-CISAz94