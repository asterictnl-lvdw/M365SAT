# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz3142($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz3142"
		FindingName	     = "CIS Az 3.1.4.3 - 'Agentless container vulnerability assessment' component status is set to 'Off'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Agentless vulnerability scanning will examine container images - whether running or in storage - for vulnerable configurations."
		Remediation	     = "Navigate to the PowerShellScript link, select the subscription and under Settings & Monitoring toggle Agentless container vulnerability assessment to On."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Overview-Container protection in Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction' },
		@{ 'Name' = 'IR-2: Preparation - setup incident notification'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-incident-response#ir-2-preparation---setup-incident-notification' },
		@{ 'Name' = 'How does Defender for Cloud collect data?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components?tabs=autoprovision-containers' })
	}
	return $inspectorobject
}

function Audit-CISAz3142
{
	try
	{
		#Get current Subscription ID
		$Subscription = (Get-AzContext).Subscription.Id
		$Settings = ((Invoke-AzRestMethod -Method GET -Path "/subscriptions/$($Subscription)/providers/Microsoft.Security/pricings/CloudPosture?api-version=2023-01-01").Content | ConvertFrom-Json).properties.extensions | Where-Object {$_.name -eq 'ContainerRegistriesVulnerabilityAssessments'}
		
		if ($Settings.isEnabled -eq 'False')
		{
			$finalobject = Build-CISAz3142("False")
			return $finalobject
		}
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CISAz3142