# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz93($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz93"
		FindingName	     = "CIS Az 9.3 - 'FTP State' is not set to 'FTPS Only' or 'Disabled'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "FTP is an unencrypted network protocol that will transmit data - including passwords - in clear-text. The use of this protocol can lead to both data and credential compromise, and can present opportunities for exfiltration, persistence, and lateral movement."
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = 'Set-AzWebApp -ResourceGroupName <resource group name> -Name <app name> -FtpsState <Disabled or FtpsOnly>'
		DefaultValue	 = "By default, App Service Authentication is disabled"
		ExpectedValue    = "App Service Authentication is enabled"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Deploy your app to Azure App Service using FTP/S'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/deploy-ftp?tabs=portal' },
		@{ 'Name' = 'Security in Azure App Service'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/overview-security' },
		@{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-data-protection#dp-3-encrypt-sensitive-data-in-transit' },
		@{ 'Name' = 'PV-6: Rapidly and automatically remediate vulnerabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-6-rapidly-and-automatically-remediate-vulnerabilities' })
	}
	return $inspectorobject
}

function Audit-CISAz93
{
	try
	{
		
		$Violation = @()
		$WebApps = Get-AzWebApp -ProgressAction SilentlyContinue
		foreach ($WebApp in $WebApps){
			$App = Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue | Select-Object -ExpandProperty SiteConfig
			if ($App.FtpsState -eq 'AllAllowed'){
				$Violation += $WebApp.DefaultHostName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz93($Violation)
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
return Audit-CISAz93