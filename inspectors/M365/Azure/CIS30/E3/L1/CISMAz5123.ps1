#Requires -module Az.Accounts
# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes'
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5123($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5123"
		FindingName	     = "CIS MAz 5.1.2.3 - Non-Admin Users can create new tenants!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "10"
		Description	     = "Restricting tenant creation prevents unauthorized or uncontrolled deployment of resources and ensures that the organization retains control over its infrastructure. User generation of shadow IT could lead to multiple, disjointed environments that can make it difficult for IT to manage and secure the organization's data, especially if other users in the organization began using these tenants for business purposes under the misunderstanding that they were secured by the organization's security team."
		Remediation	     = "Change the value to False (Yes) to restrict non-admins from creating tenants! Or use the PowerShell script to restrict non-admins."
		PowerShellScript = '$params = @{ DefaultUserRolePermissions = @{ AllowedToCreateTenants = $false } }; Update-MgBetaPolicyAuthorizationPolicy -AuthorizationPolicyId "authorizationPolicy" -BodyParameter $params'
		DefaultValue	 = "AllowedToCreateTenants: True"
		ExpectedValue    = "AllowedToCreateTenants: False"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Restrict member users default permissions'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions' })
	}
	return $inspectorobject
}

function Audit-CISMAz5123
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
			$NonAdminTenants | Format-Table -AutoSize | Out-File "$path\CISMAz5123-AuthorizationDefaultRolePermissions.txt"
			$finalobject = Build-CISMAz5123($AffectedOptions)
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
return Audit-CISMAz5123