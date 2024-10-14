# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'Notify about alerts with the following severity' is Set to High
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz31014($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz31014"
		FindingName	     = "CIS Az 3.1.14 - Notify about alerts with the following severity is not Set to High"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "3"
		Description	     = "Enabling security alert emails ensures that security alert emails are received from Microsoft. This ensures that the right people are aware of any potential security issues and are able to mitigate the risk."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "High"
		ExpectedValue    = "High"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure email notifications for alerts and attack paths'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' },
		@{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' })
	}
	return $inspectorobject
}

function Audit-CISAz31014
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties | select-object alertNotifications -ExpandProperty alertNotifications -ErrorAction SilentlyContinue
		
		if ($Settings.minimalSeverity -notmatch "High")
		{
			$finalobject = Build-CISAz31014($Settings.minimalSeverity)
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
return Audit-CISAz31014