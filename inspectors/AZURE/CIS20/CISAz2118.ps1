# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure That 'All users with the following roles' is set to 'Owner'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2118($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2118"
		FindingName	     = "CIS Az 2.1.18 - All users with the following roles is not set to Owner"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "1"
		Description	     = "Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "Owner"
		ExpectedValue    = "Owner"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Quickstart: Configure email notifications for security alerts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' })
	}
	return $inspectorobject
}

function Audit-CISAz2118
{
	try
	{
		$SubScriptionID = Get-AzSubscription
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubScriptionID.id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties | select-object notificationsByRole -ExpandProperty notificationsByRole -ErrorAction SilentlyContinue | select-object roles -ExpandProperty roles -ErrorAction SilentlyContinue
		
		if ($Settings -notmatch 'Owner')
		{
			$finalobject = Build-CISAz2118($Settings)
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
return Audit-CISAz2118