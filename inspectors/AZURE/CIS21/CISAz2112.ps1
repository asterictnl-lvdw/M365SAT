# Date: 25-1-2023
# Version: 1.0
# Benchmark: CISAz Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that Microsoft Defender Recommendation for 'Apply system updates' status is 'Completed'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2112($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2112"
		FindingName	     = "CIS Az 2.1.12 - Microsoft Defender Recommendation for 'Apply system updates' status is not equal to 'Completed'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "1"
		Description	     = "Enabling Microsoft Defender allows for greater defense-in-depth, with threat detection provided by the Microsoft Security Response Center (MSRC)."
		Remediation	     = "Use the powershell command and replace SubScriptionName with the corresponding subscription which has a Free Pricing Tier at the moment."
		PowerShellScript = 'Register-AzResourceProvider -ProviderNamespace "Microsoft.PolicyInsights"; '
		DefaultValue	 = "By default, patches are not automatically deployed"
		ExpectedValue    = "Patches are automatically deployed"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'PV-6: Rapidly and automatically remediate vulnerabilities'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-posture-vulnerability-management#pv-6-rapidly-and-automatically-remediate-vulnerabilities' },
			@{ 'Name' = 'Microsoft Defender for Cloud pricing'; 'URL' = 'https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/' },
		@{ 'Name' = 'Enable vulnerability scanning with the integrated Qualys scanner'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-vm' })
	}
	return $inspectorobject
}

function Audit-CISAz2112
{
	try
	{
		# Actual Script
		$definitions = Get-AzPolicyDefinition
		$policy = Get-AzPolicyAssignment -IncludeDescendent | Select-Object -ExpandProperty properties | Where-Object {$_.properties.displayname -eq "Machines should be configured to periodically check for missing system updates"} | Select-Object -Property Scope, PolicyDefinitionID, DisplayName | Format-List
		
		# Validation
		if ([string]::IsNullOrEmpty($policy) -or $policy.count -eq 0)
		{
			$finalobject = Build-CISAz2112("Policy not created!")
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
return Audit-CISAz2112