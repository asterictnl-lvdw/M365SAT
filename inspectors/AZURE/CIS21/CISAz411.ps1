# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Auditing' is set to 'On' (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz411($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz411"
		FindingName	     = "CIS Az 4.1.1 - Setting: 'Auditing' on Azure SQL Servers is not set to 'On'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "TThe Azure platform allows a SQL server to be created as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing policy applied on the SQL database does not override auditing policy and settings applied on the particular SQL server where the database is hosted."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzSqlServerAudit -ResourceGroupName <RGNAME> -ServerName <SQLServername> -RetentionInDays 90 -LogAnalyticsTargetState Enabled -EventHubTargetState Enabled -BlobStorageTargetState Enabled'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Remediate security recommendations'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/implement-security-recommendations' },
		@{ 'Name' = 'Auditing for Azure SQL Database and Azure Synapse Analytics'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-overview?view=azuresql' })
	}
	return $inspectorobject
}

function Audit-CISAz411
{
	try
	{
		$violation = @()
		$SQLServers = Get-AzSqlServer
		foreach ($SQLServer in $SQLServers){
			$Server = Get-AzSqlServerAudit -ResourceGroupName $SQLServer.ResourceGroupName -ServerName $SQLServer.ServerName
			if ($Server.BlobStorageTargetState -or $Server.EventHubTargetState -or $Server.LogAnalyticsTargetState -eq "Disabled"){
				$violation += $SQLServer.ServerName
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz411($violation)
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
return Audit-CISAz411