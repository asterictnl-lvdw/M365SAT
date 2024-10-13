# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz31010($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz31010"
		FindingName	     = "CIS Az 3.1.10 - Microsoft Defender Recommendations for 'Apply system updates' status are not all 'Completed'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "2"
		Description	     = "Windows and Linux virtual machines should be kept up-to-date. Microsoft Defender for Cloud retrieves a list of available security and critical updates from Windows Update or Windows Server Update Services (WSUS), depending on which service is configured on a Windows VM. The security center also checks for the latest updates in Linux systems. If a VM is missing a system update, the security center will recommend system updates be applied. "
		Remediation	     = "Use the Link in PowerShellScript to navigate to the Recommendations section."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5'
		DefaultValue	 = ">0"
		ExpectedValue    = "0"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Connect your Azure subscriptions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/connect-azure-subscription' },
		@{ 'Name' = 'Overview of Microsoft Defender for Resource Manager'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-resource-manager-introduction' },
		@{ 'Name' = 'Microsoft Defender for Cloud pricing'; 'URL' = 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/' },
		@{ 'Name' = 'Security alerts and incidents'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/alerts-overview' },
		@{ 'Name' = 'LT-1: Enable threat detection capabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-logging-threat-detection#lt-1-enable-threat-detection-capabilities' })
	}
	return $inspectorobject
}

function Audit-CISAz31010
{
	try
	{
		$Violation = @()
		# Actual Script
		$Recommendations = Get-AzSecurityTask | Where-Object {$_.RecommendationType -match "system updates"}
		ForEach ($Recommendation in $Recommendations){
			$Violation += "$($Recommendation.RecommendationType) : $($Recommendation.ResourceId)"
		}
		
		# Validation
		if ($Violation.Count -igt 0)
		{
			$finalobject = Build-CISAz31010($Violation)
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
return Audit-CISAz31010