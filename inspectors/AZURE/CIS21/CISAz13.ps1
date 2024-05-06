# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.1.0
# Product Family: Microsoft Azure
# Purpose: Ensure that 'Multi-Factor Auth Status' is 'Enabled' for all Non-Privileged Users
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz113($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISAz13"
		FindingName	     = "CIS Az 1.1.3 - Multi-Factor Auth Status is 'Disabled' for some non-privileged Users"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Multi-factor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multi-factor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multi-factor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk"
		Remediation	     = "Please enable MFA for all users through the Admin Portal. You can also use the legacy script by Adminroid"
		PowerShellScript = 'https://admindroid.sharepoint.com/:u:/s/external/EVzUDxQqxWdLj91v3mhAipsBt0GqNmUK5b4jFXPr181Svw?e=OOcfQn&isSPOFile=1'
		DefaultValue	 = "All Users have no MFA Enabled"
		ExpectedValue    = "All Users have MFA Enabled"
		ReturnedValue    = "$findings Users have MFA Disabled"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'How it works: Microsoft Entra multifactor authentication'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mfa-howitworks' },
			@{ 'Name' = 'Enable per-user Microsoft Entra multifactor authentication to secure sign-in events'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-userstates' },
			@{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' })
	}
	return $inspectorobject
}

function Audit-CISAz113
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
			$affectedusers | Format-Table -AutoSize | Out-File "$path\CISAz113UsersNonMFA.txt"
			$finalobject = Build-CISAz113($affectedusers.Count)
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
		# Set the properties to retrieve
		$select = @(
			'id',
			'DisplayName',
			'userprincipalname',
			'mail'
		)
		$properties = $select + "AssignedLicenses"
		# Get enabled, disabled or both users
		switch ($enabled)
		{
			"true" { $filter = "AccountEnabled eq true and UserType eq 'member'" }
			"false" { $filter = "AccountEnabled eq false and UserType eq 'member'" }
			"both" { $filter = "UserType eq 'member'" }
		}
		
		# Check if UserPrincipalName(s) are given
		if ($UserPrincipalName)
		{
			Write-host "Get users by name" -ForegroundColor Cyan
			$users = @()
			foreach ($user in $UserPrincipalName)
			{
				try
				{
					$users += Get-MgUser -UserId $user -Property $properties | select $select -ErrorAction Stop
				}
				catch
				{
					[PSCustomObject]@{
						DisplayName	      = " - Not found"
						UserPrincipalName = $User
						isAdmin		      = $null
						MFAEnabled	      = $null
					}
				}
			}
		}
		else
		{
			if ($IsLicensed)
			{
				# Get only licensed users
				$users = Get-MgUser -Filter $filter -Property $properties -all | Where-Object { ($_.AssignedLicenses).count -gt 0 } | Select-Object $select
			}
			else
			{
				$users = Get-MgUser -Filter $filter -Property $properties -all | Select-Object $select
			}
		}
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
return Audit-CISAz113