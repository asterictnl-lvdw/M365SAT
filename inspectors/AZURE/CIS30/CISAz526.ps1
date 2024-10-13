# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz526($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz526"
		FindingName	     = "CIS Az 5.2.6 - Server parameter 'log_connections' is set to 'OFF' for some PostgreSQL single servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Enabling log_connections helps PostgreSQL Database to log attempted connection to the server, as well as successful completion of client authentication. Log data can be used to identify, troubleshoot, and repair configuration errors and suboptimal performance."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_connections -Value on'
		DefaultValue	 = "On"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure server parameters in Azure Database for PostgreSQL - Flexible Server via the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal' },
		@{ 'Name' = 'LT-3: Enable logging for security investigation'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-3-enable-logging-for-security-investigation' })
	}
	return $inspectorobject
}

function Audit-CISAz526
{
	try
	{
		$violation = @()
		$PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/servers'}
		foreach ($PostGreServer in $PostGreServers){
			$Setting = Get-AzPostgreSqlConfiguration -ResourceGroupName $PostGreServer.ResourceGroupName -ServerName $PostGreServer.Name -Name log_connections
			if ($Setting.Value -ne 'on'){
				$violation += $PostGreServer.Name
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz526($violation)
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
return Audit-CISAz526