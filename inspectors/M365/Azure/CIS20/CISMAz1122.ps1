#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz1122($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz1122"
		FindingName	     = "CIS MAz 1.1.22 - Non-Admin Users can create new tenants!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Restricting tenant creation prevents unauthorized or uncontrolled deployment of resources and ensures that the organization retains control over its infrastructure. User generation of shadow IT could lead to multiple, disjointed environments that can make it difficult for IT to manage and secure the organization's data, especially if other users in the organization began using these tenants for business purposes under the misunderstanding that they were secured by the organization's security team."
		Remediation	     = "Change the value to False (Yes) to restrict non-admins from creating tenants! Or use the PowerShell script to restrict non-admins."
		PowerShellScript = '$params = @{ DefaultUserRolePermissions = @{ AllowedToCreateTenants = $false } }; Update-MgBetaPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -BodyParameter $params'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Restrict member users default permissions'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions#restrict-member-users-default-permissions' })
	}
	return $inspectorobject
}

function Audit-CISMAz1122
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$NonAdminTenants = Invoke-MgGraphRequest -Method GET https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy/defaultUserRolePermissions
		
		# Validation
		if ($NonAdminTenants.allowedToCreateTenants -ne $False)
		{
			$AffectedOptions += "allowedToCreateTenants: $($NonAdminTenants.allowedToCreateTenants)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$finalobject = Build-CISMAz1122($AffectedOptions)
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
return Audit-CISMAz1122