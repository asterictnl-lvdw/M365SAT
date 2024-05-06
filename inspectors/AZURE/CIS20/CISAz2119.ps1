# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Additional email addresses' is Configured with a Security Contact Email 
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
		FindingName	     = "CIS Az 2.1.19 - Additional email addresses is not Configured with any Security Contact Email"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Microsoft Defender for Cloud emails the Subscription Owner to notify them about security alerts. Adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "Owner"
		ExpectedValue    = "Owner"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Quickstart: Configure email notifications for security alerts'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' })
	}
	return $inspectorobject
}

function Audit-CISAz2119
{
	try
	{
		$SubScriptionID = Get-AzSubscription
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubScriptionID.id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties
		
		if ([string]::IsNullOrEmpty($Settings.emails))
		{
			$finalobject = Build-CISAz2119("No Emailaddresses specified")
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