# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'Notify about alerts with the following severity' is Set to High
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2119($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2119"
		FindingName	     = "CIS Az 2.1.19 - Notify about alerts with the following severity is not Set to High"
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
		References	     = @(@{ 'Name' = 'Quickstart: Configure email notifications for security alerts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' })
	}
	return $inspectorobject
}

function Audit-CISAz2119
{
	try
	{
		# https://management.azure.com/subscriptions/b1e7d08a-3165-4386-b924-7926fe4af0f0
		$SubScriptionID = Get-AzSubscription
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubScriptionID.id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties | select-object alertNotifications -ExpandProperty alertNotifications -ErrorAction SilentlyContinue
		
		if ($Settings.minimalSeverity -notmatch "High")
		{
			$finalobject = Build-CISAz2119($Settings.minimalSeverity)
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
return Audit-CISAz2119