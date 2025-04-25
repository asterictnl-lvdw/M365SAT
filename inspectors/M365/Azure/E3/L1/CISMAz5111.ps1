# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5111
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5111"
        ID               = "5.1.1.1"
        Title            = "(L1) Ensure Security Defaults is disabled"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "True for tenants created later than 2019, False for tenants created before 2019"
        ExpectedValue    = "False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Security defaults in Azure Active Directory (Azure AD) are preconfigured security settings that make it easier to protect your organization from common threats. While beneficial for basic security, disabling these defaults allows for customized and potentially more robust security measures."
        Impact           = "The potential impact associated with disabling of Security Defaults is dependent upon the security controls implemented in the environment. It is likely that most organizations disabling Security Defaults plan to implement equivalent controls to replace Security Defaults. It may be necessary to check settings in other Microsoft products, such as Azure, to ensure settings and functionality are as expected when disabling security defaults for MS365."
        Remediation 	 = '$params = @{ IsEnabled = $false } Update-MgPolicyIdentitySecurityDefaultEnforcementPolicy -BodyParameter $params'
        References       = @(
            @{ 'Name' = 'Security defaults in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' },
            @{ 'Name' = 'Introducing security defaults'; 'URL' = 'https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/introducing-security-defaults/ba-p/1061414' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5111
{
	try
	{
		# Actual Script
		$SecureDefaultsState = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy
		
		# Validation
		if ($SecureDefaultsState.isEnabled -eq $true)
		{
			$SecureDefaultsState | Format-Table -AutoSize | Out-File "$path\CISMAz5111-SecureDefaultEnforcementPolicy.txt"
			$endobject = Build-CISMAz5111 -ReturnedValue ($SecureDefaultsState.isEnabled) -Status "FAIL" -RiskScore "4" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5111 -ReturnedValue ($SecureDefaultsState.isEnabled) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5111 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5111