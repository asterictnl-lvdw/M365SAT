# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Microsoft Entra authentication is Configured for SQL Servers (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz515($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz515"
		FindingName	     = "CIS Az 5.1.5 - Data encryption is set to 'Off' on some SQL Databases"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Azure SQL Database transparent data encryption helps protect against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName <Resource Group Name> -ServerName <SQL Server Name> -DatabaseName <Database Name> -State "Enabled"'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Transparent data encryption for SQL Database, SQL Managed Instance, and Azure Synapse Analytics'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview?view=azuresql&tabs=azure-portal' },
		@{ 'Name' = 'DP-4: Enable data at rest encryption by default'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-4-enable-data-at-rest-encryption-by-default' })
	}
	return $inspectorobject
}

function Audit-CISAz515
{
	try
	{
		$violation = @()
		$SQLServers = Get-AzSqlServer
		foreach ($SQLServer in $SQLServers){
			$Databases = Get-AzSqlDatabase -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName
			ForEach ($Database in $Databases){
				$Encryption = Get-AzSqlDatabaseTransparentDataEncryption -ServerName $SQLServer.ServerName -ResourceGroupName $SQLServer.ResourceGroupName -DatabaseName $Database.DatabaseName
				if ($Encryption.State -eq "Disabled" -and $Encryption.DatabaseName -ne "master"){
					$violation += $SQLServer.ServerName
				}
			}
		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz515($violation)
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
return Audit-CISAz515