# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz523($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz523"
		FindingName	     = "CIS Az 5.2.3 - server parameter 'connection_throttle.enable' is set to 'OFF' for some PostgreSQL flexible servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Enabling connection throttling helps the PostgreSQL Database to Set the	verbosity of logged messages. This in turn generates query and error logs with respect to concurrent connections that could lead to a successful Denial of Service	(DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name connection_throttle.enable -Value on'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure server parameters in Azure Database for PostgreSQL - Flexible Server via the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' },
		@{ 'Name' = 'Configure logging'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-logging#configure-logging' })
	}
	return $inspectorobject
}

function Audit-CISAz523
{
	try
	{
		$violation = @()
		$PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/flexibleServers'}
		foreach ($PostGreServer in $PostGreServers){
			$Setting = Get-AzPostgreSqlFlexibleServerConfiguration -ResourceGroupName $PostGreServer.ResourceGroupName -ServerName $PostGreServer.Name -Name connection_throttle.enable
			if ($Setting.Value -ne 'on'){
				$violation += $PostGreServer.Name
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz523($violation)
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
return Audit-CISAz523