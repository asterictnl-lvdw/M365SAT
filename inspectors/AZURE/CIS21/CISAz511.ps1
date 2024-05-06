# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that a 'Diagnostic Setting' exists for Subscription Activity Logs (Manual)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz511($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz511"
		FindingName	     = "CIS Az 5.1.1 - 'Diagnostic Setting' does not exist for some Subscription Activity Logs"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "A diagnostic setting controls how a diagnostic log is exported. By default, logs are retained only for 90 days. Diagnostic settings should be defined so that logs can be exported and stored for a longer duration in order to analyze security activities within an Azure subscription."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'New-AzDiagnosticSetting'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Overview of Azure platform logs'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview#export-the-activity-log-with-a-log-profile' })
	}
	return $inspectorobject
}

function Audit-CISAz511
{
	try
	{
		$Violation = @()
		# Due to Get-AzDiagnosticSetting issues this only works with the Azure CLI: https://aka.ms/installazurecliwindows
		$AzCommand = (Get-Module -Name Az.Monitor -WarningAction SilentlyContinue).ExportedCommands
		if ($AzCommand.Count -ne 0)
		{
			$Settings = Invoke-Expression "az monitor diagnostic-settings subscription list --subscription $((Get-AzSubscription).Id) -WarningAction SilentlyContinue | ConvertFrom-Json | Select * -ExpandProperty value | Select * -ExpandProperty logs | Select category,enabled"
			foreach ($setting in $Settings)
			{
				if ($setting.Enabled -eq $false)
				{
					$Violation += $setting.category
				}
			}
			if (-not [string]::IsNullOrEmpty($Settings2))
			{
				$Violation += "ApplicationInsights Returned Null"
			}
		}
		else
		{
				# Get all Azure Subscriptions
			$Subs = Get-AzSubscription
			# Set array
			$DiagResults = @()
			# Loop through all Azure Subscriptions
			foreach ($Sub in $Subs) {
				Set-AzContext $Sub.id | Out-Null
				# Get all Azure resources for current subscription
				$Resources = Get-AZResource
				# Get all Azure resources which have Diagnostic settings enabled and configured
				foreach ($res in $Resources) {
					$resId = $res.ResourceId
					$DiagSettings = Get-AzDiagnosticSetting -ResourceId $resId -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne $null }
					foreach ($diag in $DiagSettings) {
						If ($diag.StorageAccountId) {
							[string]$StorageAccountId= $diag.StorageAccountId
							[string]$storageAccountName = $StorageAccountId.Split('/')[-1]
						}
						If ($diag.EventHubAuthorizationRuleId) {
							[string]$EventHubId = $diag.EventHubAuthorizationRuleId
							[string]$EventHubName = $EventHubId.Split('/')[-3]
						}
						If ($diag.WorkspaceId) {
							[string]$WorkspaceId = $diag.WorkspaceId
							[string]$WorkspaceName = $WorkspaceId.Split('/')[-1]
						}
						# Store all results for resource in PS Object
						$item = [PSCustomObject]@{
							ResourceName = $res.name
							DiagnosticSettingsName = $diag.name
							StorageAccountName =  $StorageAccountName
							EventHubName =  $EventHubName
							WorkspaceName =  $WorkspaceName
							# Extracting delatied porerties into string format.
							Metrics = ($diag.Metrics | ConvertTo-Json -Compress | Out-String).Trim()
							Logs =  ($diag.Logs | ConvertTo-Json -Compress | Out-String).Trim()
							Subscription = $Sub.Name
							ResourceId = $resId
							DiagnosticSettingsId = $diag.Id
							StorageAccountId =  $StorageAccountId
							EventHubId =  $EventHubId
							WorkspaceId = $WorkspaceId
						}
						$DiagResults += $item
					}
				}
			}
		}

		if ($DiagResults.count -eq 0 -or $Violation.count -igt 0){
			$finalobject = Build-CISAz511($violation)
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
return Audit-CISAz511