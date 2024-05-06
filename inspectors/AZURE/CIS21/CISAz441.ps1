# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Enforce SSL connection' is set to 'Enabled' for Standard MySQL Database Server (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz441($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz441"
		FindingName	     = "CIS Az 4.4.1 - Enforce SSL connection is not set to 'Enabled' for some Standard MySQL Database Servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzMySqlServer -ResourceGroupName <server>.ResourceGroupName -Name <Server>.Name -ssl-enforcement Enabled'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'SSL/TLS connectivity in Azure Database for MySQL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/single-server/concepts-ssl-connection-security' },
		@{ 'Name' = 'Configure SSL connectivity in your application to securely connect to Azure Database for MySQL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/single-server/how-to-configure-ssl' })
	}
	return $inspectorobject
}

function Audit-CISAz441
{
	try
	{
		$violation = @()
		
		$MySqlServers = Get-AzMySqlServer
		
		foreach ($MySqlServer in $MySqlServers){
			if ($MySqlServer.SslEnforcement -eq $false){
				$violation += $MySqlServer.Name
			}
		}

		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz441($violation)
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
return Audit-CISAz441