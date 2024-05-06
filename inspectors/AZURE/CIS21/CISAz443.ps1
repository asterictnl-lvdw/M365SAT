# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL Database Server (Manual)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz443($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz443"
		FindingName	     = "CIS Az 4.4.3 - server parameter 'audit_log_enabled' is not set to 'ON' for some MySQL Database Servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Enabling audit_log_enabled helps MySQL Database to log items such as connection attempts to the server, DDL/DML access, and more. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzMySqlConfiguration -Name audit_log_enabled -ResourceGroupName PowershellMySqlTest -ServerName mysql-test -Value On'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure and access audit logs for Azure Database for MySQL in the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/single-server/how-to-configure-audit-logs-portal' })
	}
	return $inspectorobject
}

function Audit-CISAz443
{
	try
	{
		$violation = @()
		$MySqlServers = Get-AzMySqlServer
		foreach ($MySqlServer in $MySqlServers){
			$Settings = Get-AzMySqlConfiguration -ResourceGroupName $MySqlServer.ResourceGroupName -Name $MySqlServer.Name -Name audit_log_enabled
			if ($MySqlServer.Value -ne "On"){
				$violation += $MySqlServer.Name
			}
		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz443($violation)
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
return Audit-CISAz443