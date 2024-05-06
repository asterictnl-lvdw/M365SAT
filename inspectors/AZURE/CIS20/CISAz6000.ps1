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


function Build-CISAz6000($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz6000"
		FindingName	     = "CIS Az 6.x.xx - Azure Monitoring and Logging Incompliancy Detected"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "There are some Azure Monitoring and Logging Settings Incompliant. Please review the values which are reported back into the report"
		Remediation	     = "No PowerShell Script Available"
		PowerShellScript = '-'
		DefaultValue	 = "-"
		ExpectedValue    = "-"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = '-'; 'URL' = '-' })
	}
	return $inspectorobject
}

function Audit-CISAz6000
{
	try
	{
		$AffectedSettings = @()
		# Due to Get-AzDiagnosticSetting issues this only works with the Azure CLI: https://aka.ms/installazurecliwindows
		$Check1 = Get-AzNetworkWatcher -WarningAction SilentlyContinue
		foreach ($Check in $Check1)
		{
			if ($Check.provisioningState -notmatch 'Succeeded')
			{
				$AffectedSettings += $Check.Name
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