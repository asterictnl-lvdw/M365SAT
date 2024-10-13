# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz524($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz524"
		FindingName	     = "CIS Az 5.2.4 - server parameter 'connection_throttle.enable' is set to 'OFF' for some PostgreSQL flexible servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Configuring logfiles.retention_days determines the duration in days that Azure Database for PostgreSQL retains log files. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name logfiles.retention_days -Value <4-7>'
		DefaultValue	 = "3"
		ExpectedValue    = "Between 4 and 7"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure server parameters in Azure Database for PostgreSQL - Flexible Server via the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal' },
		@{ 'Name' = 'LT-6: Configure log storage retention'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-6-configure-log-storage-retention' })
	}
	return $inspectorobject
}

function Audit-CISAz524
{
	try
	{
		$violation = @()
		$PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/flexibleServers'}
		foreach ($PostGreServer in $PostGreServers){
			$Setting = Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName $PostGreServer.ResourceGroupName -ServerName $PostGreServer.Name -Name logfiles.retention_days
			if ($Setting.Value -ile 3){
				$violation += $PostGreServer.Name
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz524($violation)
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
return Audit-CISAz524