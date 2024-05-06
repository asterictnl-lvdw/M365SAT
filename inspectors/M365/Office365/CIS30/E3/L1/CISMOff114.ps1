# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft 365
# Purpose: Checks if Guest Users are found within your tenant
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff114($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff114"
		FindingName	     = "CIS MOff 1.1.4 - Guest Users Found in your Tenant!"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "0"
		Description	     = "It is recommended to review your Guest Users to determine if they still need access within your tenant or that you can safely remove them."
		Remediation	     = "Remove inactive and unneccesary guest account access to your tenant."
		PowerShellScript = 'https://admin.microsoft.com/'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.Count
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'About Administrative Roles'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/about-admin-roles?view=o365-worldwide" },
			@{ 'Name' = 'Permissions in the Security and Compliance Center'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/permissions-in-the-security-and-compliance-center?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMOff114
{
	Try
	{
		$GuestUsers = (Get-MgUser -All -Property UserType, UserPrincipalName | Where-Object { $_.UserType -ne "Member" })
		
		If ($GuestUsers.Count -igt 0)
		{
			$GuestUsers | Format-Table -AutoSize UserPrincipalName, UserType | Out-File "$path\CISMOff114-GuestAccounts.txt"
			$endobject = Build-CISMOff114($GuestUsers)
			Return $endobject
		}
		
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Audit-CISMOff114


