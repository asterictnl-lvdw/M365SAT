# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz3135($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz3135"
		FindingName	     = "CIS Az 3.1.3.5 - File Integrity Monitoring component status is set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "FIM provides a detection mechanism for compromised files. When FIM is enabled, critical system files are monitored for changes that might indicate a threat actor is attempting to modify system files for lateral compromise within a host operating system."
		Remediation	     = "Navigate to the PowerShellScript link, select the subscription and under Settings & Monitoring toggle Agentless scanning for Machines to On."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'File Integrity Monitoring in Microsoft Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-overview' },
		@{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' },
		@{ 'Name' = 'File Integrity Monitoring using Microsoft Defender for Endpoint'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/file-integrity-monitoring-enable-defender-endpoint' })
	}
	return $inspectorobject
}

function Audit-CISAz3135
{
	try
	{
		#Get current Subscription ID
		$Subscription = (Get-AzContext).Subscription.Id
		# Since this requires Defender for Servers Plan 2 I cannot audit this, but this is the URL you can check to determine. All you need to do is modify the eq statement to the corresponding value.
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($Subscription)/providers/Microsoft.Security/pricings/CloudPosture?api-version=2023-01-01").Content | ConvertFrom-Json).properties.extensions | Where-Object {$_.name -eq ''}
		
		if ($Settings.isEnabled -eq 'False')
		{
			$finalobject = Build-CISAz3135("False")
			return $finalobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz3135