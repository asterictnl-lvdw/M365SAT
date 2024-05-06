# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Users can create Azure AD Tenants' is set to 'No'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz130($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz130"
		FindingName	     = "CIS Az 1.3 - Users can create Azure AD Tenants"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "It is recommended to only allow an administrator to create new tenants. This prevent users from creating new Azure AD or Azure AD B2C tenants and ensures that only authorized users are able to do so."
		Remediation	     = "Use the Powershell Script to modify the policy to disallow Tenant Creation by unauthorized users"
		PowerShellScript = '$RolePermissions = @{}; $RolePermissions["allowedToCreateTenants"] = $False; Update-MgPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -DefaultUserRolePermissions $RolePermissions'
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = "$findings"
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'What are the default user permissions in Azure Active Directory?'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/users-default-permissions' },
			@{ 'Name' = 'Tenant Creator Role'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#tenant-creator' })
	}
	return $inspectorobject
}

function Audit-CISAz130
{
	try
	{
		# Actual Script
		$AuthorizationPolicy = (Invoke-MgGraphRequest -Method GET "https://graph.microsoft.com/beta/policies/authorizationPolicy/authorizationPolicy")
		
		# Validation
		if ($AuthorizationPolicy.defaultUserRolePermissions.allowedToCreateTenants -eq $true)
		{
			$finalobject = Build-CISAz130($AuthorizationPolicy.defaultUserRolePermissions.allowedToCreateTenants)
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
return Audit-CISAz130