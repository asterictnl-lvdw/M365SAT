# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz435($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz435"
		FindingName	     = "CIS Az 4.3.5 - Server Parameter 'connection_throttling' is set to 'OFF' for some PostgreSQL Database Servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Enabling connection_throttling helps the PostgreSQL Database to Set the verbosity of logged messages. This in turn generates query and error logs with respect to concurrent connections that could lead to a successful Denial of Service (DoS) attack by exhausting connection resources. A system can also fail or be degraded by an overload of legitimate users. Query and error logs can be used to identify, troubleshoot, and repair configuration errors and sub-optimal performance."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name connection_throttling -Value on'
		DefaultValue	 = "on"
		ExpectedValue    = "on"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure server parameters in Azure Database for PostgreSQL - Single Server via the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-configure-server-parameters-using-portal' })
	}
	return $inspectorobject
}

function Audit-CISAz435
{
	try
	{
		$violation = @()
		$PostGresServers = Get-AzPostgreSqlServer
		foreach ($PostGresServer in $PostGresServers){
			$Settings = Get-AzPostgreSqlConfiguration -ResourceGroupName $PostGresServer.ResourceGroupName -ServerName $PostGresServer.Name -Name connection_throttling
			if ($PostGresServer.value -ne "On"){
				$violation += $PostGresServer.Name
			}
		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz435($violation)
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
return Audit-CISAz435