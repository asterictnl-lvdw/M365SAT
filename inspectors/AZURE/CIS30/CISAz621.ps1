# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Activity Log Alert exists for Create Policy Assignment
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz621($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz621"
		FindingName	     = "CIS Az 6.2.1 - Activity Log Alert do not exist for Create Policy Assignment"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Monitoring for create policy assignment events gives insight into changes done in 'Azure policy - assignments' and can reduce the time it takes to detect unsolicited changes."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzActivityLogAlert'
		DefaultValue	 = "By default, no monitoring alerts are created."
		ExpectedValue    = "an Activity Log Alert Rule for Microsoft.Authorization/policyAssignments/write"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Classic alerts in Azure Monitor to retire in June 2019'; 'URL' = 'https://azure.microsoft.com/en-us/updates/classic-alerting-monitoring-retirement/' },
		@{ 'Name' = 'Create or edit an activity log, service health, or resource health alert rule'; 'URL' = 'https://learn.microsoft.com/en-in/azure/azure-monitor/alerts/alerts-create-activity-log-alert-rule?tabs=activity-log' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
		@{ 'Name' = 'Create or edit a log search alert rule'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-create-log-alert-rule' })
	}
	return $inspectorobject
}

function Audit-CISAz621
{
	try
	{
		$Violation = @()
		$Subscriptions = Get-AzSubscription

		foreach ($Subscription in $Subscriptions){
			$LogAlert = Get-AzActivityLogAlert -SubscriptionId $Subscription.Id | Where-Object {$_.ConditionAllOf.Equal -match "Microsoft.Authorization/policyAssignments/write"} | Select-Object Location,Name,Enabled,ResourceGroupName,ConditionAllOf
			if ([string]::IsNullOrEmpty($LogAlert)){
				$violation = $Subscription.Name
			}
		}

		if ($Violation.count -igt 0){
			$finalobject = Build-CISAz621($violation)
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
return Audit-CISAz621