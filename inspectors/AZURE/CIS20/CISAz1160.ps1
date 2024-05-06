# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Guest invite restrictions' is set to "Only users assigned to specific admin roles can invite guest users"
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz1160($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz1160"
		FindingName	     = "CIS Az 1.16 - Guest invite restrictions is not set to 'Only users assigned to specific admin roles can invite guest users'"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Restricting invitations to users with specific administrator roles ensures that only authorized accounts have access to cloud resources. This helps to maintain 'Need to Know' permissions and prevents inadvertent access to data. By default the setting Guest invite restrictions is set to Anyone in the organization can invite guest users including guests and non-admins. This would allow anyone within the organization to invite guests and non-admins to the tenant, posing a security risk."
		Remediation	     = "Use the PowerShell Script to mitigate this issue:"
		PowerShellScript = 'Update-MgPolicyAuthorizationPolicy -AllowInvitesFrom  "adminsAndGuestInviters"'
		DefaultValue	 = "everyone"
		ExpectedValue    = "adminsAndGuestInviters"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Configure external collaboration settings'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/external-identities/external-collaboration-settings-configure' },
			@{ 'Name' = 'PA-3: Manage lifecycle of identities and entitlements'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-3-manage-lifecycle-of-identities-and-entitlements' },
			@{ 'Name' = 'GS-2: Define and implement enterprise segmentation/separation of duties strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-2-define-and-implement-enterprise-segmentationseparation-of-duties-strategy' },
			@{ 'Name' = 'GS-6: Define and implement identity and privileged access strategy'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-governance-strategy#gs-6-define-and-implement-identity-and-privileged-access-strategy' })
	}
	return $inspectorobject
}

function Audit-CISAz1160
{
	try
	{
		# Actual Script
		$Policy = Get-MgPolicyAuthorizationPolicy
		
		# Validation
		if ($Policy.AllowInvitesFrom -ne 'adminsAndGuestInviters')
		{
			$finalobject = Build-CISAz1160($Policy.AllowInvitesFrom)
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
return Audit-CISAz1160