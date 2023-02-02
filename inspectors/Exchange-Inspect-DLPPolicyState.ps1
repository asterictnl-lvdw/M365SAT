# This is an DLPPolicyState Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the DLP Policy is existing and enabled correctly
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Define Path
$path = @($OutPath)

function Build-DLPPolicyState($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0025"
		FindingName	     = "DLP Policies Not Enabled and Enforced"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "0.0"
		Description	     = "Policies were found in a state other than 'Enable'. The state of the policy determines what, if any, actions are taken when the policy is triggered. Reasons that a policy may be in a state other than 'Enable' include testing, policy deprecation, and auditing as well as potentially nefarious reasons. Policy state definitions are: - Enable: The policy is enabled for actions and notifications. This is the default value. - Disable: The policy is disabled. - TestWithNotifications: No actions are taken, but notifications are sent. - TestWithoutNotifications: An audit mode where no actions are taken, and no notifications are sent."
		Remediation	     = "Validate that the current state of the policies returned are expected and remediate as necessary."
		PowerShellScript = ''
		DefaultValue	 = "Enabled"
		ExpectedValue    = "Enabled"
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		References	     = @(@{ 'Name' = 'Learn about data loss prevention'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/dlp-learn-about-dlp?view=o365-worldwide" },
			@{ 'Name' = 'Create, test, and tune a DLP policy'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/compliance/create-test-tune-dlp-policy?view=o365-worldwide" })
	}
	return $inspectorobject
}

Function Inspect-DLPPolicyState
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
			$endobject = Build-DLPPolicyState($policies)
			return $endobject
		}
		Return $null
		
	}
	Catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
	
}
return Inspect-DLPPolicyState


