# Date: 26-09-2024
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz531($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz531"
		FindingName	     = "CIS Az 5.3.1 - Server parameter 'require_secure_transport' is set to 'OFF' for some MySQL flexible servers"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "SSL connectivity helps to provide a new layer of security by connecting database server to client applications using Secure Sockets Layer (SSL). Enforcing SSL connections between database server and client applications helps protect against 'man in the middle' attacks by encrypting the data stream between the server and application."
		Remediation	     = "Use the PowerShell script to remediate the issue."
		PowerShellScript = 'Update-AzMySqlFlexibleServerConfiguration -ResourceGroupName <resourceGroup> -ServerName <serverName> -Name require_secure_transport -Value on'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'TLS and SSL'; 'URL' = 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking#tls-and-ssl' },
		@{ 'Name' = 'DP-3: Encrypt sensitive data in transit'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-data-protection#dp-3-encrypt-sensitive-data-in-transit' })
	}
	return $inspectorobject
}

function Audit-CISAz531
{
	try
	{
		$violation = @()
		$MySqlServers = Get-AzResource | Where-Object {$_.ResourceType -eq 'Microsoft.DBforMySQL/flexibleServers'}
		foreach ($MySqlServer in $MySqlServers){
			$Setting = Get-AzMySqlFlexibleServerConfiguration -ResourceGroupName $MySqlServer.ResourceGroupName -ServerName $PostGreSeMySqlServerrver.Name -Name require_secure_transport
			if ($Setting.Value -ne 'on'){
				$violation += $MySqlServer.Name
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz531($violation)
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
return Audit-CISAz531