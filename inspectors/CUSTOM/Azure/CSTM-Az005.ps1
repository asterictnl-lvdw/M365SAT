# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Azure
# Purpose: Checks if Password Sync is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CSTM-Az005($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Az005"
		FindingName	     = "CSTM-Az005 - Password Synchronization Enabled"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "0"
		Description	     = "Password hash synchronization is one of the sign-in methods used to accomplish hybrid identity. Azure AD Connect synchronizes a hash, of the hash, of a user's password from an on-premises Active Directory instance to a cloud-based Azure AD instance."
		Remediation	     = "Follow Microsoft guidance and best practices to ensure your hybrid configuration meets your business needs and policies."
		PowerShellScript = 'Please use the StackOverflow Solution to disable Password Synchronization'
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'What is password hash synchronization with Azure AD?'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-phs" },
			@{ 'Name' = 'Is there any ps command to disable password hash sync?'; 'URL' = "https://stackoverflow.com/questions/62036670/is-there-any-ps-command-to-disable-password-hash-sync" })
	}
}

Function Inspect-CSTM-Az005
{
	Try
	{
		
		$syncTime = (Invoke-MgGraphRequest -Method GET 'https://graph.microsoft.com/beta/organization').Value.onPremisesLastPasswordSyncDateTime
		
		If ($null -ne $syncTime)
		{
			$endobject = Build-CSTM-Az005("Password Synchronization is enabled. Last synced $syncTime")
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

Return Inspect-CSTM-Az005


