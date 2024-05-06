# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure no Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP) (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz412($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz412"
		FindingName	     = "CIS Az 4.1.2 - Some Azure SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Azure SQL Server includes a firewall to block access to unauthorized connections. More granular IP addresses can be defined by referencing the range of addresses available from specific datacenters. By default, for a SQL server, a Firewall exists with StartIp of 0.0.0.0 and EndIP of 0.0.0.0 allowing access to all the Azure services. Additionally, a custom rule can be set up with StartIp of 0.0.0.0 and EndIP of 255.255.255.255 allowing access from ANY IP over the Internet. In order to reduce the potential attack surface for a SQL server, firewall rules should be defined with more granular IP addresses by referencing the range of addresses available from specific datacenters."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzSqlServerFirewallRule -ResourceGroupName <resource group name> -ServerName <server name> -FirewallRuleName <firewall rule name> -StartIpAddress <IP Address other than 0.0.0.0> -EndIpAddress <IP Address other than 0.0.0.0 or 255.255.255.255>'
		DefaultValue	 = "By default, Allow access to Azure Services is set to NO"
		ExpectedValue    = "YES"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure a Windows Firewall for Database Engine Access'; 'URL' = 'https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-a-windows-firewall-for-database-engine-access?view=sql-server-2017' },
		@{ 'Name' = 'Azure SQL Database and Azure Synapse IP firewall rules'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/firewall-configure?view=azuresql' },
		@{ 'Name' = 'sp_set_database_firewall_rule (Azure SQL Database)'; 'URL' = 'https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-set-database-firewall-rule-azure-sql-database?view=azuresqldb-current' })
	}
	return $inspectorobject
}

function Audit-CISAz412
{
	try
	{
		$violation = @()
		$SQLServers = Get-AzSqlServer
		foreach ($SQLServer in $SQLServers){
			$Server = Get-AzSqlServerFirewallRule -ResourceGroupName $SQLServer.ResourceGroupName -ServerName $SQLServer.ServerName
			if ($Server.StartIpAddress -eq "0.0.0.0" -or $Server.EndIpAddress -eq "0.0.0.0" -or $Server.FirewallRuleName -eq "firewallRules_AllowAllAzureIps"){
				$violation += $SQLServer.ServerName
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz412($violation)
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
return Audit-CISAz412