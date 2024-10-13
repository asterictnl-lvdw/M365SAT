# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz533($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz533"
		FindingName	     = "CIS Az 5.3.3 - Server parameter 'audit_log_enabled' is set to 'OFF' for some MySQL flexible servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Enabling audit_log_enabled helps MySQL Database to log items such as connection attempts to the server, DDL/DML access, and more. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name audit_log_enabled -Value on'
		DefaultValue	 = "OFF"
		ExpectedValue    = "ON"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Tutorial: Configure audit logs by using Azure Database for MySQL - Flexible Server'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/tutorial-configure-audit' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
		@{ 'Name' = 'Configure auditing by using the Azure CLI'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/tutorial-configure-audit#configure-auditing-by-using-the-azure-cli' })
	}
	return $inspectorobject
}

function Audit-CISAz533
{
	try
	{
		$violation = @()
		$MySqlServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforMySQL/flexibleServers'}
		foreach ($MySqlServer in $MySqlServers){
			$Setting = Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName $MySqlServer.ResourceGroupName -ServerName $PostGreSeMySqlServerrver.Name -Name audit_log_enabled
			if ($Setting.Value -ne 'on'){
				$violation += $MySqlServer.Name
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz533($violation)
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
return Audit-CISAz533