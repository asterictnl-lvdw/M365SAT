# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Any of the ASC Default Policy Settings are Not Set to 'Disabled'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz2114($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz2114"
		FindingName	     = "CIS Az 2.1.14 - ASC Default Policy Setting is not Enforced!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "3"
		Description	     = "A security policy defines the desired configuration of your workloads and helps ensure compliance with company or regulatory security requirements. ASC Default policy is associated with every subscription by default. ASC default policy assignment is a set of security recommendations based on best practices. Enabling recommendations in ASC default policy ensures that Azure security center provides the ability to monitor all of the supported recommendations and optionally allow automated action for a few of the supported recommendations."
		Remediation	     = "You can change the settings in the URL written in PowerShellScript."
		PowerShellScript = 'https://portal.azure.com/#view/Microsoft_Azure_Security/SecurityMenuBlade/~/EnvironmentSettings'
		DefaultValue	 = "EnforcementMode: Default / Parameters: Null"
		ExpectedValue    = "EnforcementMode: Default / Parameters: Null"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Manage security policies'; 'URL' = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/tutorial-security-policy' })
	}
	return $inspectorobject
}

function Audit-CISAz2114
{
	try
	{
		$Setting = Get-AzPolicyAssignment -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Where-Object { $_.Name -eq 'SecurityCenterBuiltIn' } | Select-Object -ExpandProperty Properties 
		
		
		if ($Setting.EnforcementMode -match "DoNotEnforce" -or $Setting.Parameters -contains "Disabled")
		{
			$finalobject = Build-CISAz2114("EnforcementMode: $($Setting.EnforcementMode) Parameters: $($Setting.Parameters)")
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
return Audit-CISAz2114