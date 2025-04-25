# Benchmark: CIS Microsoft Azure v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz624
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz624"
        ID               = "6.2.4"
        Title            = "(L2) Ensure that A Multi-factor Authentication Policy Exists for All Users"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "Starting October 2024, MFA will be required for all accounts by default."
        ExpectedValue    = "A Policy"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Multifactor authentication is strongly recommended to increase the confidence that a claimed identity can be proven to be the subject of the identity. This results in a stronger authentication chain and reduced likelihood of exploitation."
        Impact           = "There is an increased cost, as Conditional Access policies require Microsoft Entra ID P1 or P2. Similarly, this may require additional overhead to maintain if users lose access to their MFA."
        Remediation      = "Create a Conditional Access policy to enforce Multi-Factor Authentication (MFA) for all users through the Microsoft Entra admin portal."
        References       = @(
            @{ 'Name' = 'Common Conditional Access policy: Require MFA for all users'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa' },
            @{ 'Name' = 'Troubleshooting Conditional Access using the What If tool'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access-what-if' },
            @{ 'Name' = 'Conditional Access insights and reporting'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-insights-reporting' },
            @{ 'Name' = 'IM-7: Restrict resource access based on conditions'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-7-restrict-resource-access-based-on--conditions' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz624
{
	try
	{
		# Actual Script
		$Violation = @()
		#Since the authflow function is in beta we must call the beta module to retrieve the settings
		$Policies = Get-MgBetaIdentityConditionalAccessPolicy |  Where-Object { ($_.Conditions.Users.IncludeUsers -eq 'All') -and ($_.Conditions.Users.ExcludeUsers.Count -ige 1) -and ($_.Conditions.Applications.IncludeApplications -eq "All") -and ($_.GrantControls.BuiltInControls -eq "mfa")}
		if ([string]::IsNullOrEmpty($Policies))
		{
			$Violation += "No Conditional Access Policy (Correctly) defining Multi-factor Authentication Policy Exists for All Users!"
		}
		else
		{
			foreach($Policy in $Policies){
				if ($Policies.State -eq 'disabled') {
					$Violation += "Conditional Access Policy: $($Policy.DisplayName) defining Multi-factor Authentication Policy for All Users is not enabled!"
				}
				else
				{
					$Policies | Format-Table -AutoSize | Out-File "$path\CISAz624-MFAPoliciesForAllUsers.txt"
				}
			}
		}
		
		# Validation

		if ($Violation.Count -ne 0)
		{
			$finalobject = Build-CISAz624 -ReturnedValue ($Violation) -Status "FAIL" -RiskScore "15" -RiskRating "High"
			return $finalobject
		}else
		{
			$endobject = Build-CISAz624 -ReturnedValue "Conditional Access Policy defining Multi-factor Authentication Policy for All Users is enabled!" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz624 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz624