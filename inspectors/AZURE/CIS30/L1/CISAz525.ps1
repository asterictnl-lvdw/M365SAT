# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz525($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz525"
		FindingName	     = "CIS Az 5.2.5 - 'Allow public access from any Azure service within Azure to this server' for some PostgreSQL flexible servers is enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "If access from Azure services is enabled, the server's firewall will accept connections from all Azure resources, including resources not in your subscription. This is usually	not a desired configuration. Instead, set up firewall rules to allow access from specific network ranges or VNET rules to allow access from specific virtual networks."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Remove-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name <ruleName>'
		DefaultValue	 = "The Azure Postgres firewall is set to block all access by default."
		ExpectedValue    = "Block all access by default."
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Firewall rules in Azure Database for PostgreSQL - Flexible Server'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-firewall-rules' },
		@{ 'Name' = 'Create and manage Azure Database for PostgreSQL - Flexible Server firewall rules using the Azure CLI'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-manage-firewall-cli' },
		@{ 'Name' = 'NS-1: Establish network segmentation boundaries'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-1-establish-network-segmentation-boundaries' },
		@{ 'Name' = 'NS-6: Deploy web application firewall'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-network-security#ns-6-deploy-web-application-firewall' })
	}
	return $inspectorobject
}

function Audit-CISAz525
{
	try
	{
		$violation = @()
		$PostGreServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforPostgreSQL/flexibleServers'}
		foreach ($PostGreServer in $PostGreServers){
			$Setting = Get-AzPostgreSqlFlexibleServerFirewallRule -ResourceGroupName $PostGreServer.ResourceGroupName -ServerName $PostGreServer.Name
			if (-not [string]::IsNullOrEmpty($Setting.StartIPAddress) -or -not [string]::IsNullOrEmpty($Setting.EndIPAddress)){
				$violation += $PostGreServer.Name
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz525($violation)
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
return Audit-CISAz525