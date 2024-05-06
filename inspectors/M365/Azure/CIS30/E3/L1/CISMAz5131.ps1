# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure a dynamic group for guest users is created
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5131($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5131"
		FindingName	     = "CISMAz 5.1.3.1 - No dynamic group for guest users is created!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "4"
		Description	     = "Dynamic Groups allow for an automated method to assign group membership. Guest user accounts will be automatically added to this group and through this existing conditional access rules, access controls and other security measures will ensure that new guest accounts are restricted in the same manner as existing guest accounts."
		Remediation	     = "Use the PowerShell Script to create a Dynamic Group for Guests"
		PowerShellScript = '$params = @{ DisplayName = "Dynamic Test Group"  MailNickname = "DynGuestUsers"  MailEnabled = $false SecurityEnabled = $true GroupTypes = "DynamicMembership"  MembershipRule = "(user.userType -eq "Guest")" MembershipRuleProcessingState = "On"}; New-MgGroup @params'
		DefaultValue	 = "0"
		ExpectedValue    = "At least 1"
		ReturnedValue    = "$findings"
		Impact		     = "4"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Create or update a dynamic group in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-create-rule' },
			@{ 'Name' = 'Dynamic membership rules for groups in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership' },
			@{ 'Name' = 'Create dynamic groups in Microsoft Entra B2B collaboration'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/use-dynamic-groups' })
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
			$finalobject = Build-CISMAz5131("0")
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
return Audit-CISMAz5131