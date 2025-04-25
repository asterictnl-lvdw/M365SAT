# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5131
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5131"
        ID               = "5.1.3.1"
        Title            = "(L1) Ensure a dynamic group for guest users is created"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "0"
        ExpectedValue    = "At least 1"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Dynamic Groups allow for an automated method to assign group membership. Guest user accounts can be automatically managed, ensuring consistent application of security controls to new and existing guest accounts."
        Impact           = "Without a dynamic group for guest users, it may be challenging to enforce consistent access control policies, which can increase the risk of unauthorized access or inconsistent application of security measures."
        Remediation 	 = '$params = @{ DisplayName = "Dynamic Test Group"  MailNickname = "DynGuestUsers"  MailEnabled = $false SecurityEnabled = $true GroupTypes = "DynamicMembership"  MembershipRule = "(user.userType -eq "Guest")" MembershipRuleProcessingState = "On"}; New-MgGroup @params'
        References       = @(
            @{ 'Name' = 'Create or update a dynamic group in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-create-rule' },
            @{ 'Name' = 'Dynamic membership rules for groups in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership' },
            @{ 'Name' = 'Create dynamic groups in Microsoft Entra B2B collaboration'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/use-dynamic-groups' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5131
{
	try
	{
		# Actual Script
		$groups = Get-MgGroup | Where-Object { $_.GroupTypes -contains "DynamicMembership" }
		$groups | Format-Table DisplayName, GroupTypes, MembershipRule
		$groups | Format-Table -AutoSize | Out-File "$path\CISMAz5131-DynamicMembershipGroups.txt"
		
		# Validation
		if ([string]::IsNullOrEmpty($groups))
		{
			$endobject = Build-CISMAz5131 -ReturnedValue ($groups.Count) -Status "FAIL" -RiskScore "4" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5131 -ReturnedValue ($groups.Count) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5131 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}
return Audit-CISMAz5131