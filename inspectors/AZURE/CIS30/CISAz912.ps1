# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz912($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz912"
		FindingName	     = "CIS Az 9.12 - 'Remote debugging' is set to 'On' for some App Services"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Disabling remote debugging on Azure App Service is primarily about enhancing security. Remote debugging opens a communication channel that can be exploited by attackers. By disabling it, you reduce the number of potential entry points for unauthorized access. If remote debugging is enabled without proper access controls, it can allow unauthorized users to connect to your application, potentially leading to data breaches or malicious code execution. During a remote debugging session, sensitive information might be exposed. Disabling remote debugging helps ensure that such data remains secure. This minimizes the use	of remote access tools to reduce risk."
		Remediation	     = "Use the PowerShell script below to remediate the issue."
		PowerShellScript = 'Set-AzWebApp -ResourceGroupName <resource_group_name> -Name <app_name> -RemoteDebuggingEnabled $false'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Remote Debug ASP.NET Core on Azure App Service (Windows)'; 'URL' = 'https://learn.microsoft.com/en-us/visualstudio/debugger/remote-debugging-azure-app-service?view=vs-2022' },
		@{ 'Name' = 'PV-2: Audit and enforce secure configurations'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-posture-vulnerability-management#pv-2-audit-and-enforce-secure-configurations' })
	}
	return $inspectorobject
}

function Audit-CISAz912
{
	try
	{
		$Violation = @()
		$WebApps = Get-AzWebApp -ProgressAction SilentlyContinue
		foreach ($WebApp in $WebApps){
			$App = (Get-AzWebApp -ResourceGroupName $WebApp.ResourceGroup -Name $WebApp.Name -ProgressAction SilentlyContinue).SiteConfig
			if ($App.RemoteDebuggingEnabled -ne $false){
				$Violation += $WebApp.DefaultHostName
			}
		}
		
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz912($Violation)
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
return Audit-CISAz912