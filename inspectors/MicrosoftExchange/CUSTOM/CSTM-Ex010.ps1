# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if a DLP Policy is enabled and enforced
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex010($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex010"
		FindingName	     = "CSTM-Ex010 - DLP Policies Not Enabled and Enforced"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "0"
		Description	     = "Policies were found in a state other than 'Enable'. The state of the policy determines what, if any, actions are taken when the policy is triggered. Reasons that a policy may be in a state other than 'Enable' include testing, policy deprecation, and auditing as well as potentially nefarious reasons. Policy state definitions are: - Enable: The policy is enabled for actions and notifications. This is the default value. - Disable: The policy is disabled. - TestWithNotifications: No actions are taken, but notifications are sent. - TestWithoutNotifications: An audit mode where no actions are taken, and no notifications are sent."
		Remediation	     = "Validate that the current state of the policies returned are expected and remediate as necessary."
		PowerShellScript = 'New-DlpPolicy -Name "Example" -Template "TEMPLATEHERE";Set-DlpPolicy "Example" -State Enabled'
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = $findings
		Impact		     = "0"
		Likelihood	     = "0"
		RiskRating	     = "Informational"
		Priority		 = "Informational"
		References	     = @(@{ 'Name' = 'Learn about data loss prevention'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp?view=o365-worldwide" },
			@{ 'Name' = 'Create, test, and tune a DLP policy'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/create-test-tune-dlp-policy?view=o365-worldwide" })
	}
	return $inspectorobject
}

Function Inspect-CSTM-Ex010
{
	Try
	{
		
		$dlpPolicies = Get-DlpCompliancePolicy | Where-Object { $_.Mode -notlike "Enable" }
		
		$policies = @()
		
		foreach ($policy in $dlpPolicies)
		{
			$policies += "$($policy.Name) state is $($policy.mode)"
		}
		
		If ($policies.Count -gt 0)
		{
			$endobject = Build-CSTM-Ex010($policies)
			return $endobject
		}
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}
return Inspect-CSTM-Ex010


