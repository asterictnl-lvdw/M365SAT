# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz96($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz96"
		FindingName	     = "CIS Az 9.6 - 'Basic Authentication' is not set to 'Disabled'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Basic Authentication introduces an identity silo which can produce privileged access to a resource. This can be exploited in numerous ways and represents a significant vulnerability and attack vector."
		Remediation	     = "Select the AppService, Go to Settings > Configuration, Go to General Settings > Toggle both SCM Basic Auth and FTP Basic Auth to 'Off'"
		PowerShellScript = 'https://portal.azure.com/?feature.tokencaching=true&feature.internalgraphapiversion=true#browse/Microsoft.Web%2Fsites'
		DefaultValue	 = "Both parameters for Basic Authentication (SCM and FTP) are set to On (True) by default."
		ExpectedValue    = "False"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Disable basic authentication in App Service deployments'; 'URL' = 'https://learn.microsoft.com/en-us/azure/app-service/configure-basic-auth-disable?tabs=portal' })
	}
	return $inspectorobject
}

function Audit-CISAz96
{
	try
	{
		$Violation = @()
		$SubscriptionId = Get-AzContext
		$WebApps = Get-AzWebApp -ProgressAction SilentlyContinue
		foreach ($WebApp in $WebApps){
			$Policy1 = ((Invoke-AzRestMethod "https://management.azure.com/subscriptions/$($SubscriptionId.Subscription.Id)/resourceGroups/$($WebApp.ResourceGroup)/providers/Microsoft.Web/sites/$($WebApp.Name)/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01").Content | ConvertFrom-Json)
			$Policy2 = ((Invoke-AzRestMethod "https://management.azure.com/subscriptions/$($SubscriptionId.Subscription.Id)/resourceGroups/$($WebApp.ResourceGroup)/providers/Microsoft.Web/sites/$($WebApp.Name)/basicPublishingCredentialsPolicies/scm?api-version=2022-03-01").Content | ConvertFrom-Json)
			if ($Policy1.properties.allow -eq $True){
				$Violation += "$($WebApp.DefaultHostName): FTP Basic Auth Publishing Credentials Enabled"
			}
			if ($Policy2.properties.allow -eq $True){
				$Violation += "$($WebApp.DefaultHostName): SCM Basic Auth Publishing Credentials Enabled"
			}
		}
		
		if ($Violation.count -igt 0)
		{
			$finalobject = Build-CISAz96($Violation)
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
return Audit-CISAz96