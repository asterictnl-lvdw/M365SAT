# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Auditing' Retention is 'greater than 90 days' (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz516($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz516"
		FindingName	     = "CIS Az 5.1.6 - Auditing Retention is not greater than 90 days"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzSqlServerAudit -ResourceGroupName "<resource group name>" -ServerName "<SQL Server name>" -BlobStorageTargetState/-EventHubTargetState/LogAnalyticsTargetState Enabled'
		DefaultValue	 = "By default, SQL Server audit storage is disabled."
		ExpectedValue    = ">90 days"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Auditing for Azure SQL Database and Azure Synapse Analytics'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview?view=azuresql' },
		@{ 'Name' = 'LT-6: Configure log storage retention'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-6-configure-log-storage-retention' })
	}
	return $inspectorobject
}

function Audit-CISAz516
{
	try
	{
		$violation = @()
		$SQLServers = Get-AzSqlServer
		foreach ($SQLServer in $SQLServers){
			$ServerAudits = Get-AzSqlServerAudit -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName
			ForEach ($ServerAudit in $ServerAudits){
				if ($ServerAudit.LogAnalyticsTargetState -eq "Enabled")
				{
					$InsightWorkSpace = Get-AzOperationalInsightsWorkspace | Where-Object {$_.ResourceId -eq $ServerAudit.WorkspaceResourceId}
					if ($InsightWorkSpace.retentionInDays -ilt 90){
						$violation += $SQLServer.ServerName
					}
				}
				else
				{
					if ($ServerAudit.RetentionInDays -ilt 90){
						$violation += $SQLServer.ServerName
					}
				}
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz516($violation)
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
return Audit-CISAz516