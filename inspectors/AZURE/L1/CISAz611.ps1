# Benchmark: CIS Microsoft Azure v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz611
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz611"
        ID               = "6.1.1"
        Title            = "(L1) Ensure that 'security defaults' is enabled in Microsoft Entra ID"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "True for tenants created later than 2019, False for tenants created before 2019"
        ExpectedValue    = "True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Security defaults in Azure Active Directory (Azure AD) make it easier to be secure and help protect your organization. Security defaults contain preconfigured security settings for common attacks."
        Impact           = "This recommendation should be implemented initially and then may be overridden by other service/product specific CIS Benchmarks. Administrators should also be aware that certain configurations in Microsoft Entra ID may impact other Microsoft services such as Microsoft 365."
        Remediation      = 'Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy" -Body (@{"isEnabled"="true"} | ConvertTo-Json)'
        References       = @(
            @{ 'Name' = 'Security defaults in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' },
            @{ 'Name' = 'Introducing security defaults'; 'URL' = 'https://techcommunity.microsoft.com/t5/microsoft-entra-blog/introducing-security-defaults/ba-p/1061414' },
            @{ 'Name' = 'IM-2: Protect identity and authentication systems'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-2-protect-identity-and-authentication-systems' }
        )
    }
    return $inspectorobject
}


function Audit-CISAz611
{
	try
	{
		# Actual Script
		$SecureDefaultsState = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
		
		# Validation
		if ($SecureDefaultsState.isEnabled -eq $true)
		{
			$SecureDefaultsState | Format-Table -AutoSize | Out-File "$path\CISAz611-SecureDefaultEnforcementPolicy.txt"
			$endobject = Build-CISAz611 -ReturnedValue ($SecureDefaultsState.isEnabled) -Status "FAIL" -RiskScore "4" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz611 -ReturnedValue ($SecureDefaultsState.isEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz611 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISAz611