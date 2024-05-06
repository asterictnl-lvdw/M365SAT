# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL Database Server (Manual)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz444($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz444"
		FindingName	     = "CIS Az 4.4.4 - server parameter 'audit_log_events' is not set to 'CONNECTION' for some MySQL Database Servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Enabling CONNECTION helps MySQL Database to log items such as successful and failed connection attempts to the server. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzMySqlConfiguration -Name audit_log_events -ResourceGroupName PowershellMySqlTest -ServerName mysql-test -Value CONNECTION'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "CONNECTION"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'SSL/TLS connectivity in Azure Database for MySQL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-ssl-connection-security' },
		@{ 'Name' = 'Configure SSL connectivity in your application to securely connect to Azure Database for MySQL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/single-server/how-to-configure-ssl' })
	}
	return $inspectorobject
}

function Audit-CISAz444
{
	try
	{
		$violation = @()
		$MySqlServers = Get-AzMySqlServer
		foreach ($MySqlServer in $MySqlServers){
			$Settings = Get-AzMySqlConfiguration -ResourceGroupName $MySqlServer.ResourceGroupName -Name $MySqlServer.Name -Name audit_log_events
			if ($MySqlServer.Value -ne "CONNECTION"){
				$violation += $MySqlServer.Name
			}
		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz444($violation)
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
return Audit-CISAz444