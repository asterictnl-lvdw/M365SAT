# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz527($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz527"
		FindingName	     = "CIS Az 5.2.7 - Server parameter 'log_disconnections' is set to 'OFF' for some PostgreSQL single servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Enabling log_disconnections helps PostgreSQL Database to Logs end of a session, including duration, which in turn generates query and error logs. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_disconnections -Value on'
		DefaultValue	 = "Off"
		ExpectedValue    = "On"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'What happens to Azure Database for PostgreSQL - Single Server after the retirement announcement?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/whats-happening-to-postgresql-single-server' },
		@{ 'Name' = 'What is the migration service in Azure Database for PostgreSQL?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/migrate/migration-service/overview-migration-service-postgresql' })
	}
	return $inspectorobject
}

function Audit-CISAz527
{
	try
	{
		$violation = @()
		$PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/servers'}
		foreach ($PostGreServer in $PostGreServers){
			$Setting = Get-AzPostgreSqlConfiguration -ResourceGroupName $PostGreServer.ResourceGroupName -ServerName $PostGreServer.Name -Name log_disconnections
			if ($Setting.Value -ne 'on'){
				$violation += $PostGreServer.Name
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz527($violation)
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
return Audit-CISAz527