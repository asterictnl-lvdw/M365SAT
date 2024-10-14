# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure Guest Users Are Reviewed on a Regular Basis (Manual)
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz140($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz24"
		FindingName	     = "CIS Az 2.4 - Guest Users Must be Reviewed on a Regular Basis"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "Guest users are typically added outside your employee on-boarding/off-boarding process and could potentially be overlooked indefinitely. To prevent this, guest users should be reviewed on a regular basis. During this audit, guest users should also be determined to not have administrative privileges."
		Remediation	     = "Review the Guest Accounts that are into the tenant and remove the unneccesary guest access from your tenant"
		PowerShellScript = 'Remove-MgUser -UserId <username@domain.org>'
		DefaultValue	 = "No guests"
		ExpectedValue    = "No unneccesary guests"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Properties of an Azure Active Directory B2B collaboration user'; 'URL' = 'https://learn.microsoft.com/en-us/entra/external-id/user-properties' },
			@{ 'Name' = 'Delete a user'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/add-users#delete-a-user' },
			@{ 'Name' = 'PA-4: Review and reconcile user access regularly'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-privileged-access#pa-4-review-and-reconcile-user-access-regularly' },
			@{ 'Name' = 'Microsoft Entra Plans & Pricing'; 'URL' = 'https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing' },
			@{ 'Name' = 'How To: Manage inactive user accounts'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts' },
			@{ 'Name' = 'Restore or remove a recently deleted user'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/users-restore' })
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
			$GuestUsers | Format-Table -AutoSize | Out-File "$path\CISAz140GuestUserReport.txt"
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