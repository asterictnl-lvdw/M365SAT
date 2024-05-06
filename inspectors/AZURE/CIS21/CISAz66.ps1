# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Checks if Logging and Monitoring is compliant by executing various checks
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz66($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz66"
		FindingName	     = "CIS Az 6.6 - The Network Watcher is not 'Enabled'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "Network diagnostic and visualization tools available with Network Watcher help users understand, diagnose, and gain insights to the network in Azure"
		Remediation	     = "Use the PowerShell Script to create a new AzNetworkWatcher"
		PowerShellScript = 'New-AzNetworkWatcher'
		DefaultValue	 = "Network Watcher is automatically enabled. When you create or update a virtual network in your subscription."
		ExpectedValue    = "A NetworkWatcher"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'What is Azure Network Watcher?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-overview' })
	}
	return $inspectorobject
}

function Audit-CISAz6000
{
	try
	{
		
		$AffectedSettings = @()
		$AzNetworkWatchers = Get-AzNetworkWatcher -WarningAction SilentlyContinue
		foreach ($AzNetworkWatcher in $AzNetworkWatchers)
		{
			if ($AzNetworkWatcher.provisioningState -notmatch 'Succeeded')
			{
				$AffectedSettings += $AzNetworkWatcher.Name
			}
		}
		
		
		if ($AffectedSettings.count -ne 0)
		{
			$finalobject = Build-CISAz6000($Settings.enabled)
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
return Audit-CISAz6000