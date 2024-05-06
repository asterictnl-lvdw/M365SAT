# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Enforce SSL connection' is set to 'ENABLED' for PostgreSQL Database Server (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz431($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz431"
		FindingName	     = "CIS Az 4.3.1 - Enforce SSL connection is not set to 'ENABLED' for some PostgreSQL Database Servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application."
		Remediation	     = "In Connection security > SSL Settings, ensure Enforce SSL connection is set to ENABLED."
		PowerShellScript = 'No PowerShell Script Available at the moment'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Configure TLS connectivity in Azure Database for PostgreSQL - Single Server'; 'URL' = 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-ssl-connection-security' })
	}
	return $inspectorobject
}

function Audit-CISAz431
{
	try
	{
		$violation = @()
		$PostGresServers = Get-AzPostgreSqlServer
		foreach ($PostGresServer in $PostGresServers){
			if ($PostGresServer.SslEnforcement -ne "Enabled"){
				$violation += $PostGresServer.Name
			}
		}
		$violation

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz431($violation)
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
return Audit-CISAz431