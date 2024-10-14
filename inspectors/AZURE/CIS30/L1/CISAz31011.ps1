# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz31011($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz31011"
		FindingName	     = "CIS Az 3.1.11 - Check if Microsoft Cloud Security Benchmark policies are set to 'Disabled'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "A security policy defines the desired configuration of resources in your environment and helps ensure compliance with company or regulatory security requirements. The MCSB Policy Initiative a set of security recommendations based on best practices and is associated with every subscription by default. When a policy 'Effect' is set to Audit, policies in the MCSB ensure that Defender for Cloud evaluates relevant resources for supported recommendations. To ensure that policies within the MCSB are not being missed when the Policy Initiative is evaluated, none of the policies should have an Effect of Disabled."
		Remediation	     = "Use the Link in PowerShellScript to navigate to the Recommendations section."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/5'
		DefaultValue	 = ">0"
		ExpectedValue    = "0"
		ReturnedValue    = "$findings"
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Security policies in Defender for Cloud'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/security-policy-concept' },
		@{ 'Name' = 'Remediate recommendations'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/implement-security-recommendations' },
		@{ 'Name' = 'GS-7: Define and implement logging, threat detection and incident response strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/mcsb-governance-strategy#gs-7-define-and-implement-logging-threat-detection-and-incident-response-strategy' })
	}
	return $inspectorobject
}

function Audit-CISAz31011
{
	try
	{
		$Violation = @()
		# Actual Script
		$Recommendations = (Get-AzPolicySetDefinition | Where-Object {$_.DisplayName -eq "Microsoft cloud security benchmark"}).Parameter
		$HashTable = @{}
		$Recommendations.psobject.properties | ForEach {$HashTable[$_.Name] = $_.Value}

		foreach ($param in $HashTable.GetEnumerator()){
			if ($param.Value.DefaultValue -match 'Disabled|disabled'){
				$Violation += $param.Value.metadata.displayName
			}
		}
		
		# Validation
		if ($Violation.Count -igt 0)
		{
			$Violation | Format-Table -AutoSize | Out-File "$path\CISAz31011-DefaultDisabledMCSBenchmarkPolicies.txt"
			$finalobject = Build-CISAz31011($Violation.Count)
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
return Audit-CISAz31011