# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: Checks if a Directory Sync Service Account is found
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az008($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az008"
		FindingName	     = "CSTM-Az008 - MFA Number matching & Additional Features not activated!"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "6"
		Description	     = "Without Number Matching and the additional security features enabled. Your organization and user account are vulnerable to MFA Fatigue attacks. These attacks have the goal to send as many MFA requests as possible to persuade the user to accept the request. The number matching as well eliminates the 33% guess attack which enabled the attacker to do a wild guess to see if they got the right number."
		Remediation	     = "Log into the Microsoft Entry Portal and enable or set it as Microsoft's default to enable the MFA Number matching and additional security features."
		PowerShellScript = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods/fromNav/Identity'
		DefaultValue	 = "-"
		ExpectedValue    = "-"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "2"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Microsoft enforces number matching to fight MFA fatigue attacks'; 'URL' = "https://www.bleepingcomputer.com/news/microsoft/microsoft-enforces-number-matching-to-fight-mfa-fatigue-attacks/" })
	}
}



Function Audit-CSTM-Az008
{
	Try
	{
		$NMViolation = @()
		$NumberMatching = Invoke-MgGraphRequest -Method GET https://graph.microsoft.com/beta/authenticationMethodsPolicy/authenticationMethodConfigurations/MicrosoftAuthenticator
		
		if ($NumberMatching.featureSettings.numberMatchingRequiredState.state -eq "disabled")
		{
			$NMViolation += "numberMatchingRequiredState: $($NumberMatching.featureSettings.numberMatchingRequiredState.state)"
		}
		if ($NumberMatching.featureSettings.displayLocationInformationRequiredState.state -eq "disabled")
		{
			$NMViolation += "displayLocationInformationRequiredState: $($NumberMatching.featureSettings.displayLocationInformationRequiredState.state)"
		}
		if ($NumberMatching.featureSettings.companionAppAllowedState.state -eq "disabled")
		{
			$NMViolation += "companionAppAllowedState: $($NumberMatching.featureSettings.companionAppAllowedState.state)"
		}
		if ($NumberMatching.featureSettings.displayAppInformationRequiredState.state -eq "disabled")
		{
			$NMViolation += "displayAppInformationRequiredState: $($NumberMatching.featureSettings.displayAppInformationRequiredState.state)"
		}
		
		If ($NMViolation.count -igt 0)
		{
			$endobject = Build-CSTM-Az008($NMViolation)
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

Return Audit-CSTM-Az008




