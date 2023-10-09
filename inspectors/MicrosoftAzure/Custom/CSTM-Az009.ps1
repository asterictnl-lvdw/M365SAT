# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: TempPass Settings Check
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az009($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az009"
		FindingName	     = "CSTM-Az009 - TempPass does not have the correct security settings configured"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "A Temporary Access Pass is a time-limited passcode that can be configured for multi or single use to allow users to onboard other authentication methods including passwordless methods such as Microsoft Authenticator, FIDO2 or Windows Hello for Business. A Temporary Access Pass also makes recovery easier when a user has lost or forgotten their strong authentication factor like a FIDO2 security key or Microsoft Authenticator app, but needs to sign in to register new strong authentication methods."
		Remediation	     = "Check the values via the Entra Portal "
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods/fromNav/Identity'
		DefaultValue	 = "defaultLifetimeInMinutes:60/maximumLifetimeInMinutes:480/minimumLifetimeInMinutes:60/state:disabled/defaultLength:8"
		ExpectedValue    = "defaultLifetimeInMinutes:60/maximumLifetimeInMinutes:480/minimumLifetimeInMinutes:60/state:disabled/defaultLength:12"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Using a Temporary Access Pass for Bootstrapping your Passwordless Journey!'; 'URL' = "https://identity-man.eu/2022/09/20/using-a-temporary-access-pass-for-bootstrapping-your-passwordless-journey/" })
	}
}



Function Audit-CSTM-Az000
{
	Try
	{
		$TPSettings = @()
		$TempPassSettings = Invoke-MgGraphRequest -Method GET https://graph.microsoft.com/beta/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass
		if ($TempPassSettings.state -eq "enabled")
		{
			if ($TempPassSettings.defaultLifetimeInMinutes -igt 60)
			{
				$TPSettings += "TempPass is not enabled"
			}
			if ($TempPassSettings.maximumLifetimeInMinutes -igt 480)
			{
				$TPSettings += "TempPass is not enabled"
			}
			if ($TempPassSettings.minimumLifetimeInMinutes -igt 60)
			{
				$TPSettings += "TempPass is not enabled"
			}
			if ($TempPassSettings.defaultLength -ilt 12)
			{
				$TPSettings += "defaultLength is: $($TempPassSettings.defaultLength)"
			}
		}
		else
		{
			$TPSettings += "TempPass is not enabled"
			$endobject = Build-CSTM-Az009($TPSettings)
		}
		
		
		If ($TPSettings.count -igt 0)
		{
			$endobject = Build-CSTM-Az009($TPSettings)
			Return $endobject
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

Return Audit-CSTM-Az000




