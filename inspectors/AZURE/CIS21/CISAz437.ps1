# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Allow access to Azure services' for PostgreSQL Database Server is disabled (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz437($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz437"
		FindingName	     = "CIS Az 4.3.7 - 'Allow access to Azure services' for some PostgreSQL Database Servers is not disabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually not a desired configuration. Instead, set up firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzPostgreSqlConfiguration -ResourceGroupName <ResourceGroupName> -ServerName <ServerName> -Name connection_throttling -Value on'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure server parameters in Azure Database for PostgreSQL - Single Server via the Azure portal'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/how-to-configure-server-parameters-using-portal' })
	}
	return $inspectorobject
}

function Audit-CISAz437
{
	try
	{
		$violation = @()
		
		$PostGresServers = Get-AzPostgreSqlServer
		foreach ($PostGresServer in $PostGresServers){
			$Rules = Get-AzPostgreSqlFirewallRule -ResourceGroupName $PostGresServer.ResourceGroupName -ServerName $PostGresServer.Name
			foreach ($Rule in $Rules)
			{
				if ($Rule.Name -contains "AllowAllWindowsAzureIps" -or $Rule.StartIPAddress -contains "0.0.0.0" -or $Rule.StartIPAddress -contains "0.0.0.0"){
					$violation += $PostGresServer.Name
				}
			}

		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz437($violation)
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
return Audit-CISAz437