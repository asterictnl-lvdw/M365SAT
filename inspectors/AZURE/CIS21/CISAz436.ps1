# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Server Parameter 'log_retention_days' is greater than 3 days for PostgreSQL Database Server (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz436($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz436"
		FindingName	     = "CIS Az 4.3.6 - Server Parameter 'log_retention_days' is greater than 3 days for some PostgreSQL Database Servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Configuring log_retention_days determines the duration in days that Azure Database for PostgreSQL retains log files. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name log_retention_days -Value <4-7>'
		DefaultValue	 = "3"
		ExpectedValue    = "between 4 and 7"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure server parameters in Azure Database for PostgreSQL - Single Server via the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-configure-server-parameters-using-portal' })
	}
	return $inspectorobject
}

function Audit-CISAz436
{
	try
	{
		$violation = @()
		$PostGresServers = Get-AzPostgreSqlServer
		foreach ($PostGresServer in $PostGresServers){
			$Settings = Get-AzPostgreSqlConfiguration -ResourceGroupName $PostGresServer.ResourceGroupName -ServerName $PostGresServer.Name -Name log_retention_days
			if ($PostGresServer.value -ilt 4){
				$violation += $PostGresServer.Name
			}
		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz436($violation)
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
return Audit-CISAz436