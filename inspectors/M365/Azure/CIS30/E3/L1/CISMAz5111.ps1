# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Checks if Secure Defaults is enabled or disabled within the tenant
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz5111($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5111"
		FindingName	     = "CISMAz 5.1.1.1 - The Security Defaults are not enabled on Azure Active Directory Tenant"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "4"
		Description	     = "Security defaults in Azure Active Directory (Azure AD) make it easier to be secure and help protect your organization. Security defaults contain preconfigured security settings for common attacks."
		Remediation	     = "Use the PowerShell Script to enable Security Defaults on Microsoft Azure Active Directory"
		PowerShellScript = '$body = $body = (@{"isEnabled"="true"} | ConvertTo-Json) ;Invoke-MgGraphRequest -Method PATCH https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy -Body $body'
		DefaultValue	 = "True for tenants created later than 2019, False for tenants created before 2019"
		ExpectedValue    = "True"
		ReturnedValue    = "$findings"
		Impact		     = "4"
		Likelihood	     = "1"
		RiskRating	     = "Low"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Security defaults in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults' },
			@{ 'Name' = 'Introducing security defaults'; 'URL' = 'https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/introducing-security-defaults/ba-p/1061414' })
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
		if ($SecureDefaultsState.isEnabled -eq $false)
		{
			$SecureDefaultsState | Format-Table -AutoSize | Out-File "$path\CISMAz5111-SecureDefaultEnforcementPolicy.txt"
			$finalobject = Build-CISMAz5111($SecureDefaultsState.isEnabled)
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
return Audit-CISMAz5111