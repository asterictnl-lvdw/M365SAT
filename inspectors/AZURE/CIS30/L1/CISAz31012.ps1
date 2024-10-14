# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'All users with the following roles' is set to 'Owner'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz31012($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz31012"
		FindingName	     = "CIS Az 3.1.12 - Setting: All users with the following roles is not set to Owner"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "1"
		Description	     = "Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion."
		Remediation	     = "After clicking the link in PowerShellScript, navigate to Email Notifications and select Owner in the dropdown of: All users with the following roles."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "Owner"
		ExpectedValue    = "Owner"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure email notifications for alerts and attack paths'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' },
		@{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' })
	}
	return $inspectorobject
}

function Audit-CISAz31012
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties | select-object notificationsByRole -ExpandProperty notificationsByRole -ErrorAction SilentlyContinue | select-object roles -ExpandProperty roles -ErrorAction SilentlyContinue
		
		if ($Settings -notmatch 'Owner')
		{
			$finalobject = Build-CISAz31012($Settings)
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
return Audit-CISAz31012