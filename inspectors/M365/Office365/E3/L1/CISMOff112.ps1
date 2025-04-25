# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff112
{
	param(
		$ReturnedValue,
		$Status,
		$RiskScore,
		$RiskRating
	)
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		UUID			 = "CISMOff112"
		ID				 = "1.1.2"
		Title		     = "(L1) Ensure two emergency access accounts have been defined"
		ProductFamily    = "Microsoft Office 365"
		DefaultValue	 = "1"
		ExpectedValue    = "2"
		ReturnedValue    = $ReturnedValue
		Status			 = $Status
		RiskScore	     = $RiskScore
		RiskRating		 = $RiskRating
		Description	     = "In various situations, an organization may require the use of a break glass account to gain emergency access. In the event of losing access to administrative functions, an organization may experience a significant loss in its ability to provide support, lose insight into its security posture, and potentially suffer financial losses."
		Impact		     = "If care is not taken in properly implementing an emergency access account this could weaken security posture. Microsoft recommends excluding at least one of these accounts from all conditional access rules therefore passwords must have sufficient entropy and length to protect against random guesses. FIDO2 security keys may be used instead of a password for secure passwordless solution."
		Remediation		 = 'https://admin.microsoft.com/'
		References	     = @(@{ 'Name' = 'Stage 1: Critical items to do right now'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning#stage-1-critical-items-to-do-right-now" },
			@{ 'Name' = 'Manage emergency access accounts in Microsoft Entra ID'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access" },
			@{ 'Name' = 'Restricted management administrative units in Microsoft Entra ID (Preview)'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management" },
			@{ 'Name' = 'Securing privileged access for hybrid and cloud deployments in Microsoft Entra ID'; 'URL' = "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning#stage-1-critical-items-to-do-right-now" })
	}
	return $inspectorobject
}

function Audit-CISMOff112
{
	Try
	{
		
		$global_admins = (Get-MgDirectoryRoleMember -DirectoryRoleId (Get-MgDirectoryRole -Filter "DisplayName eq 'Global Administrator'").id | ForEach-Object { Get-MgDirectoryObjectById -Ids $_.id }).AdditionalProperties.userPrincipalName
		$num_global_admins = ($global_admins | Measure-Object).Count
		
		If ($num_global_admins -ilt 2)
		{
			$endobject = Build-CISMOff112 -ReturnedValue $num_global_admins -Status "FAIL" -RiskScore "12" -RiskRating "High"
			Return $endobject
		}
		else
		{
			$endobject = Build-CISMOff112 -ReturnedValue $num_global_admins -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		
	}
	catch
	{
		$endobject = Build-CISMOff112 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		Return $endobject
	}
	
}

return Audit-CISMOff112
