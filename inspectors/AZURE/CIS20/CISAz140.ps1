# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure Access Review is Set Up for External Users in Azure AD Privileged Identity Management
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz140($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz140"
		FindingName	     = "CIS Az 1.4 - Ensure Access Review is Set Up for External Users in Azure AD Privileged Identity Management"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "Guest users in the Azure AD are generally required for collaboration purposes in Office 365, and may also be required for Azure functions in enterprises with multiple Azure tenants. Guest users should be reviewed on a regular basis, at least annually. Guest users should not be granted administrative roles where possible. Guest users are typically added outside your employee on-boarding/off-boarding process and could potentially be overlooked indefinitely, leading to a potential vulnerability. Guest users should be reviewed on a monthly basis to ensure that inactive and unneeded accounts are removed."
		Remediation	     = "Review the Guest Accounts that are into the tenant and remove the unneccesary guest access from your tenant"
		PowerShellScript = 'Remove-MgUser -UserId <username@domain.org>'
		DefaultValue	 = "No guests"
		ExpectedValue    = "No unneccesary guests"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Properties of an Azure Active Directory B2B collaboration user'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/external-identities/user-properties' },
			@{ 'Name' = 'Delete a user'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/fundamentals/add-users-azure-active-directory#delete-a-user' },
			@{ 'Name' = 'Security Control v3: Privileged access'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-3-review-and-reconcile-user-access-regularly' },
			@{ 'Name' = 'Manage guest access with access reviews'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/governance/manage-guest-access-with-access-reviews' },
			@{ 'Name' = 'Azure Active Directory plans and pricing'; 'URL' = 'https://www.microsoft.com/en-us/security/business/identity-access-management/azure-ad-pricing' })
	}
	return $inspectorobject
}

function Audit-CISAz140
{
	try
	{
		# Actual Script
		$GuestUserList = @()
		$GuestUsers = Get-MgUser -Filter "UserType eq 'Guest'" | Select-Object DisplayName, UserPrincipalName, UserType -Unique
		
		# Validation
		foreach ($GuestUser in $GuestUsers)
		{
			$GuestUserList += "$($GuestUser.DisplayName): $($GuestUser.UserPrincipalName)"
		}
		
		if ($GuestUserList.Count -igt 0)
		{
			$GuestUsers | Format-Table -AutoSize | Out-File "$path\CISAz140AccessReview.txt"
			$finalobject = Build-CISAz140($GuestUserList.Count)
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
return Audit-CISAz140