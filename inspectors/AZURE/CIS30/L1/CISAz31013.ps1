# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Additional email addresses' is Configured with a Security Contact Email 
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz31013($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz31013"
		FindingName	     = "CIS Az 3.1.13 - Additional email addresses is not Configured with any Security Contact Email"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Microsoft Defender for Cloud emails the Subscription Owner to notify them about security alerts. Adding your Security Contact's email address to the 'Additional email addresses' field ensures that your organization's Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript or enable an Azure Policy for your organization."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_SubscriptionManagement/ManageSubscriptionPoliciesBlade'
		DefaultValue	 = "By default, there are no additional email addresses entered."
		ExpectedValue    = "At least 1 emailaddress"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure email notifications for alerts and attack paths'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications' },
		@{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' })
	}
	return $inspectorobject
}

function Audit-CISAz31013
{
	try
	{
		$SubscriptionId = Get-AzContext
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($SubscriptionId.Subscription.Id)/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview").content | ConvertFrom-Json).properties
		
		if ([string]::IsNullOrEmpty($Settings.emails))
		{
			$finalobject = Build-CISAz31013("No Emailaddresses specified")
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
return Audit-CISAz31013