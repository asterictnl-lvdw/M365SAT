# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.0.0
# Product Family: Microsoft Azure
# Purpose: Checks the Multi-Factor Auth Status for all Non-Priviledged Users
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5121($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz5121"
		FindingName	     = "CIS MAz 5.1.2.1 - Some User Accounts do not have MFA enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Both security defaults and conditional access with security defaults turned off are not compatible with per-user multi-factor authentication (MFA), which can lead to undesirable user authentication states. The CIS Microsoft 365 Benchmark explicitly employs Conditional Access for MFA as an enhancement over security defaults and as a replacement for the outdated per-user MFA. To ensure a consistent authentication state disable per-user MFA on all accounts."
		Remediation	     = "Please enable MFA for all users through the Admin Portal. You can also use the legacy script by Adminroid"
		PowerShellScript = 'https://admindroid.sharepoint.com/:u:/s/external/EVzUDxQqxWdLj91v3mhAipsBt0GqNmUK5b4jFXPr181Svw?e=OOcfQn&isSPOFile=1'
		DefaultValue	 = "Disabled"
		ExpectedValue    = "All Users have MFA Enabled"
		ReturnedValue    = "$findings"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Enable per-user Microsoft Entra multifactor authentication to secure sign-in events'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates#convert-users-from-per-user-mfa-to-conditional-access' },
			@{ 'Name' = 'Set up multifactor authentication for Microsoft 365'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/admin/security-and-compliance/set-up-multi-factor-authentication?view=o365-worldwide#use-conditional-access-policies' })
	}
	return $inspectorobject
}

function Audit-CISMAz5121
{
	try
	{
		# Actual Script
		$affectedusers = @()
		$users = Get-Users
		
		foreach ($user in $users)
		{
			$mfaMethods = Get-MFAMethods -userId $user.id
			if ($mfaMethods.status -eq "disabled")
			{
				$affectedusers += $user
			}
		}
		
		# Validation
		if ($affectedusers.count -gt 0)
		{
			$affectedusers | Format-Table -AutoSize | Out-File "$path\CISMAz5121-UsersNonMFA.txt"
			$finalobject = Build-CISMAz5121($affectedusers.Count)
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

Function Get-Users
{
  <#
  .SYNOPSIS
    Get users from the requested DN
  #>
	process
	{
		# Use the filter to get all members
		$filter = "UserType eq 'member'"
		
		# Set the properties to retrieve		
		$select = @(
			'id',
			'DisplayName',
			'userprincipalname',
			'mail'
		)
		$properties = $select + "AssignedLicenses"
		# Retrieve the users based on filters and properties
		$users = Get-MgUser -Filter $filter -Property $properties -all | Select-Object $select
		
		return $users
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
return Audit-CISMAz5121