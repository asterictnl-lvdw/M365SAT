# Benchmark: CIS Microsoft Azure v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz6026
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz6026"
        ID               = "6.26"
        Title            = "(L1) Ensure fewer than 5 users have global administrator assignment"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "1"
        ExpectedValue    = "Between 2 and 4"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The Global Administrator role has extensive privileges across all services in Microsoft Entra ID. It is important to minimize the number of Global Administrators to reduce the risk of unauthorized access, human error, and align with the principle of least privilege. Having at least two Global Administrators ensures the continuity of administrative tasks in case one is unavailable."
        Impact           = "Implementing this recommendation may require changes in administrative workflows or the redistribution of roles and responsibilities. Adequate training and awareness should be provided to all Global Administrators."
        Remediation      = "Use the Security and Compliance Center to review the administrative privileges granted to the users listed and determine if each user truly requires their administrative privileges. In many cases a more granular set of permissions may be appropriate. Reduce the privileges of each user as appropriate."
        References       = @(
            @{ 'Name' = 'Limit the number of Global Administrators to less than 5'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices#5-limit-the-number-of-global-administrators-to-less-than-5' },
            @{ 'Name' = 'Security guidelines for assigning roles'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide#security-guidelines-for-assigning-roles' },
            @{ 'Name' = 'Manage emergency access accounts in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access' },
            @{ 'Name' = 'PA-1: Separate and limit highly privileged/administrative users'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-1-separate-and-limit-highly-privilegedadministrative-users' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz6026
{
	Try
	{
		
		$GlobalAdminList = @()
		# Determine Id of role using the immutable RoleTemplateId value. 		
		$globalAdminRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'" 
		$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
		
		foreach ($GlobalAdmin in $globalAdmins)
		{
			$GlobalAdminList += $globalAdmin.AdditionalProperties.displayName
		}
		
		If (($globalAdmins.AdditionalProperties.Count -lt 2) -or ($globalAdmins.AdditionalProperties.Count -gt 4))
		{
			$GlobalAdminList | Format-Table -AutoSize | Out-File "$path\CISAz6026-GlobalAdmins.txt"
			$endobject = Build-CISAz6026 -ReturnedValue ($globalAdmins.AdditionalProperties.Count) -Status "FAIL" -RiskScore "12" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz6026 -ReturnedValue ($globalAdmins.AdditionalProperties.Count) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz6026 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

return Audit-CISAz6026


