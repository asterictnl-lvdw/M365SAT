# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Network Security Group Flow Log retention period is not 'greater than 90 days'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz75($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz75"
		FindingName	     = "CIS Az 7.5 - Network Security Group Flow Log retention period is not 'greater than 90 days'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "Flow logs enable capturing information about IP traffic flowing in and out of network security groups. Logs can be used to check for anomalies and give insight into suspected breaches"
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = '-'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "Disabled"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Flow logging for network security groups'; 'URL' = 'https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview' },
		@{ 'Name' = 'LT-6: Configure log storage retention'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-6-configure-log-storage-retention' })
	}
	return $inspectorobject
}

function Audit-CISAz75
{
	try
	{
		
		$Violation = @()
		$AzNetworkWatchers = Get-AzNetworkWatcher
		foreach ($AzNetworkWatcher in $AzNetworkWatchers){
			$FlowLog = Get-AzNetworkWatcherFlowLog -NetworkWatcherName $AzNetworkWatcher.Name -ResourceGroupName $AzNetworkWatcher.ResourceGroupName
			if ([string]::IsNullOrEmpty($FlowLog)){
				$Violation += $AzNetworkWatcher.Name
			}
		}
		
		
		if ($AffectedSettings.count -ne 0)
		{
			$finalobject = Build-CISAz75($Violation)
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
return Audit-CISAz75