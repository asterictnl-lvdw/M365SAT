# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Trusted Locations are defined and enabled as trusted
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz221($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz221"
		FindingName	     = "CIS Az 2.2.1 - Trusted Locations Are Not Defined or not enabled as Trusted"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "5"
		Description	     = "Defining trusted source IP addresses or ranges helps organizations create and enforce Conditional Access policies around those trusted or untrusted IP addresses and ranges. Users authenticating from trusted IP addresses and/or ranges may have less access restrictions or access requirements when compared to users that try to authenticate to Azure Active Directory from untrusted locations or untrusted source IP addresses/ranges."
		Remediation	     = "Use the PowerShell Script to enable Security Defaults on Microsoft Azure Active Directory"
		PowerShellScript = '[System.Collections.Generic.List`1[Microsoft.Open.MSGraph.Model.IpRange]]$ipRanges = @();$ipRanges.Add("yourpublicipaddress");New-AzureADMSNamedLocationPolicy -OdataType "#microsoft.graph.ipNamedLocation" -DisplayName "ipnamepolicy -IsTrusted $true -IpRanges $ipRanges; Set-AzureADMSNamedLocationPolicy -PolicyId "<ID of the policy>" -OdataType "#microsoft.graph.ipNamedLocation" -IsTrusted $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "1"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Low"
		References	     = @(@{ 'Name' = 'Conditional Access: Network assignment'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-assignment-network' },
			@{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' },
			@{ 'Name' = 'Manage emergency access accounts in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' })
	}
	return $inspectorobject
}

function Audit-CISAz221
{
	try
	{
		# Actual Script
		$NamedLocations = (Get-MgIdentityConditionalAccessNamedLocation).AdditionalProperties
		$NamedLocationInput = @()
		foreach ($Location in $NamedLocations)
		{
			$NamedLocationInput += "$($NamedLocations.ipRanges.cidrAddress): isTrusted: $($NamedLocations.isTrusted)"
		}
		
		# Validation
		if ($NamedLocationInput.count -igt 0)
		{
			$finalobject = Build-CISAz221($NamedLocationInput)
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
return Audit-CISAz221