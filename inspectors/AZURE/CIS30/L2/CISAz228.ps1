# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v3.0.0
# Product Family: Microsoft Azure
# Purpose:  Ensure Multifactor Authentication is Required to access Microsoft Admin Portals
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz228($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz228"
		FindingName	     = "CIS Az 2.2.8 - No Multi-factor Authentication Policy Exists for Microsoft Admin Portals"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Administrative Portals for Microsoft Azure should be secured with a higher level of scrutiny to authenticating mechanisms. Enabling multifactor authentication is recommended to reduce the potential for abuse of Administrative actions, and to prevent intruders or compromised admin credentials from changing administrative settings."
		Remediation	     = "Create an Conditional Access Policy to enable MFA For Admin Portals"
		PowerShellScript = 'Unavailable'
		DefaultValue	 = "null"
		ExpectedValue    = "A policy"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Conditional Access: Users, groups, and workload identities'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups' },
			@{ 'Name' = 'Common Conditional Access policy: Require multifactor authentication for admins accessing Microsoft admin portals'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-mfa-admin-portals' },
			@{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' })
	}
	return $inspectorobject
}

function Audit-CISAz228
{
	try
	{
		# Actual Script
		$Violation = @()
		#Since the authflow function is in beta we must call the beta module to retrieve the settings
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "MicrosoftAdminPortals") -and ($_.GrantControls.BuiltInControls -eq "mfa")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Multi-factor Authentication Policy Exists for Microsoft Admin Portals!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled')
				{
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy for Microsoft Admin Portals is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz227-MFAPoliciesForMicrosoftAdminPortals.txt"
				}
			}
		}
		
		# Validation
		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISAz228($Violation)
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
return Audit-CISAz228