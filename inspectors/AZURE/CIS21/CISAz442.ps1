# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'TLS Version' is set to 'TLSV1.2' (or higher) for MySQL flexible Database Server (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz442($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz442"
		FindingName	     = "CIS Az 4.4.2 - 'TLS Version' is not set to 'TLSV1.2' (or higher) for some MySQL flexible Database Servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "TLS connectivity helps to provide a new layer of security by connecting database server to client applications using Transport Layer Security (TLS). Enforcing TLS connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application."
		Remediation	     = "Use the PowerShell Script to remediate the issue."
		PowerShellScript = 'Update-AzMySqlServer -ResourceGroupName <server>.ResourceGroupName -Name <Server>.Name -MinimalTlsVersion "TLSv1_2"'
		DefaultValue	 = "v1.2"
		ExpectedValue    = "v1.2"
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

function Audit-CISAz442
{
	try
	{
		$violation = @()
		
		$MySqlServers = Get-AzMySqlServer
		
		foreach ($MySqlServer in $MySqlServers){
			if ($MySqlServer.MinimalTlsVersion -ne "TLSv1_2"){
				$violation += $MySqlServer.Name
			}
		}

		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz442($violation)
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
return Audit-CISAz442