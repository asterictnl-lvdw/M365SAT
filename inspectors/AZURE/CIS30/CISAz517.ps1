# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Auditing' Retention is 'greater than 90 days' (Automated)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz517($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz517"
		FindingName	     = "CIS Az 5.1.7 - Public Network Access is Enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "A secure network architecture requires carefully constructed network segmentation. Public Network Access tends to be overly permissive and introduces unintended vectors for threat activity."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'Set-AzSqlServer -ServerName <SQLServerName> -ResourceGroupName <ResourceGroupName> -SqlAdministratorPassword $SecureString -PublicNetworkAccess "Enabled"'
		DefaultValue	 = "By default, SQL Server audit storage is disabled."
		ExpectedValue    = ">90 days"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'NS-2: Secure cloud services with network controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-network-security#ns-2-secure-cloud-services-with-network-controls' },
		@{ 'Name' = 'Deny public network access'; 'URL' = 'https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings?view=azuresql&tabs=azure-portal#deny-public-network-access' })
	}
	return $inspectorobject
}

function Audit-CISAz517
{
	try
	{
		$violation = @()
		$SQLServers = Get-AzSqlServer
		foreach ($SQLServer in $SQLServers){
			if ($SQLServer.PublicNetworkAccess -eq 'Enabled'){
				$violation += $SQLServer.ServerName
			}
		}

		if ($violation.count -igt 0){
			$finalobject = Build-CISAz517($violation)
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
return Audit-CISAz517