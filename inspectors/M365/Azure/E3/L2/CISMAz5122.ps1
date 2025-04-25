# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5122
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5122"
        ID               = "5.1.2.2"
        Title            = "(L2) Ensure third party integrated applications are not allowed"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "AllowedToCreateApps: True"
        ExpectedValue    = "AllowedToCreateApps: False"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Third-party integrated applications connecting to services should be disabled unless there is a clear value and robust security controls in place. While some integrations are legitimate, attackers can exploit compromised accounts to grant access to third-party applications, potentially leading to data exfiltration without the need to maintain access to the breached account."
        Impact           = "Implementation of this change will impact both end users and administrators. End users will not be able to integrate third-party applications that they may wish to use. Administrators are likely to receive requests from end users to grant them permission to necessary third-party applications."
        Remediation 	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings/menuId/UserSettings'
        References       = @(
            @{ 'Name' = 'How and why applications are added to Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity-platform/how-applications-are-added' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5122
{
	try
	{
		# Actual Script
		$AuthPolicy = Get-MgPolicyAuthorizationPolicy
		
		
		# Validation
		if ($AuthPolicy.DefaultUserRolePermissions.AllowedToCreateApps -eq $true)
		{
			$AuthPolicy | Format-List | Out-File "$path\CISMAz5122-AuthorizationPolicy.txt"
			$endobject = Build-CISMAz5122 -ReturnedValue ("AllowedToCreateApps: $($AuthPolicy.DefaultUserRolePermissions.AllowedToCreateApps)") -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5122 -ReturnedValue ("AllowedToCreateApps: $($AuthPolicy.DefaultUserRolePermissions.AllowedToCreateApps)") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5122 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5122