# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Checks the Multi-Factor Auth Status for all Priviledged Users
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz112($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz112"
		FindingName	     = "CIS Az 1.1.2 - Some Admin Accounts do not have MFA enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "20"
		Description	     = "With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk."
		Remediation	     = "Please enable MFA for all Admin users through the Admin Portal. You can also use the legacy script by Adminroid"
		PowerShellScript = 'https://admindroid.sharepoint.com/:u:/s/external/EVzUDxQqxWdLj91v3mhAipsBt0GqNmUK5b4jFXPr181Svw?e=OOcfQn&isSPOFile=1'
		DefaultValue	 = "All Admins have no MFA Enabled"
		ExpectedValue    = "All Admins have MFA Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "4"
		Likelihood	     = "5"
		RiskRating	     = "Critical"
		Priority		 = "Critical"
		References	     = @(@{ 'Name' = 'How it works: Azure AD Multi-Factor Authentication'; 'URL' = 'https://learn.microsoft.com/en-us/azure/active-directory/authentication/concept-mfa-howitworks' },
			@{ 'Name' = 'Azure Active Directory Premium MFA Attributes via Graph API?'; 'URL' = 'https://stackoverflow.com/questions/41156206/azure-active-directory-premium-mfa-attributes-via-graph-api' },
			@{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' })
	}
	return $inspectorobject
}

function Audit-CISAz112
{
	try
	{
		# Actual Script
		$affectedusers = @()
		$admins = Get-Admins
		
		foreach ($admin in $admins)
		{
			$mfaMethods = Get-MFAMethods -userId $admin
			if ($mfaMethods.status -eq "disabled")
			{
				$affectedusers += $admin
			}
		}
		
		# Validation
		if ($affectedusers.count -gt 0)
		{
			$affectedusers | Format-Table -AutoSize | Out-File "$path\CIS112AdminsNonMFA.txt"
			$finalobject = Build-CISAz112($affectedusers.Count)
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

Function Get-Admins
{
  <#
  .SYNOPSIS
    Get all user with an Admin role
  #>
	process
	{
		$admins = [System.Collections.Generic.List[string]]::new()
		$roleIds = (Get-MgDirectoryRole) | Select-Object Id, DisplayName
		foreach ($role in $roleIds)
		{
			$userList = Get-MgDirectoryRoleMember -DirectoryRoleId $role.id
			foreach ($user in $userList)
			{
				$upn = (Get-MgUser -UserId $user.id).UserPrincipalName
				$admins.Add($upn)
			}
		}
		return $admins
	}
}



Function Get-MFAMethods
{
  <#
    .SYNOPSIS
      Get the MFA status of the user
  #>
	param (
		[Parameter(Mandatory = $true)]
		$userId
	)
	process
	{
		# Get MFA details for each user
		[array]$mfaData = Get-MgUserAuthenticationMethod -UserId $userId
		# Create MFA details object
		$mfaMethods = [PSCustomObject][Ordered]@{
			status		     = "-"
			authApp		     = "-"
			phoneAuth	     = "-"
			fido			 = "-"
			helloForBusiness = "-"
			emailAuth	     = "-"
			tempPass		 = "-"
			passwordLess	 = "-"
			softwareAuth	 = "-"
			authDevice	     = "-"
			authPhoneNr	     = "-"
			SSPREmail	     = "-"
		}
		ForEach ($method in $mfaData)
		{
			Switch ($method.AdditionalProperties["@odata.type"])
			{
				"#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"  {
					# Microsoft Authenticator App
					$mfaMethods.authApp = $true
					$mfaMethods.authDevice = $method.AdditionalProperties["displayName"]
					$mfaMethods.status = "enabled"
				}
				"#microsoft.graph.phoneAuthenticationMethod"                  {
					# Phone authentication
					$mfaMethods.phoneAuth = $true
					$mfaMethods.authPhoneNr = $method.AdditionalProperties["phoneType", "phoneNumber"] -join ' '
					$mfaMethods.status = "enabled"
				}
				"#microsoft.graph.fido2AuthenticationMethod"                   {
					# FIDO2 key
					$mfaMethods.fido = $true
					$fifoDetails = $method.AdditionalProperties["model"]
					$mfaMethods.status = "enabled"
				}
				"#microsoft.graph.passwordAuthenticationMethod"                {
					# Password
					# When only the password is set, then MFA is disabled.
					if ($mfaMethods.status -ne "enabled") { $mfaMethods.status = "disabled" }
				}
				"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" {
					# Windows Hello
					$mfaMethods.helloForBusiness = $true
					$helloForBusinessDetails = $method.AdditionalProperties["displayName"]
					$mfaMethods.status = "enabled"
				}
				"#microsoft.graph.emailAuthenticationMethod"                   {
					# Email Authentication
					$mfaMethods.emailAuth = $true
					$mfaMethods.SSPREmail = $method.AdditionalProperties["emailAddress"]
					$mfaMethods.status = "enabled"
				}
				"microsoft.graph.temporaryAccessPassAuthenticationMethod"    {
					# Temporary Access pass
					$mfaMethods.tempPass = $true
					$tempPassDetails = $method.AdditionalProperties["lifetimeInMinutes"]
					$mfaMethods.status = "enabled"
				}
				"#microsoft.graph.passwordlessMicrosoftAuthenticatorAuthenticationMethod" {
					# Passwordless
					$mfaMethods.passwordLess = $true
					$passwordLessDetails = $method.AdditionalProperties["displayName"]
					$mfaMethods.status = "enabled"
				}
				"#microsoft.graph.softwareOathAuthenticationMethod" {
					# ThirdPartyAuthenticator
					$mfaMethods.softwareAuth = $true
					$mfaMethods.status = "enabled"
				}
			}
		}
		Return $mfaMethods
	}
}
return Audit-CISAz112