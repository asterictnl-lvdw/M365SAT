# This is an MSTeamsExternalAccessPolicy Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Teams
# Purpose: Checks the MSTeams External Access Policy
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-MSTeamsExternalAccessPolicy($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMST0006"
		FindingName	     = "Microsoft Teams External Access Policies"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "0.0"
		Description	     = "Microsoft Teams External Access Policies"
		Remediation	     = "Review Microsoft Teams External Access Policies and validate that all results are expected, and no conflicting rules are in place."
		DefaultValue	 = "Global, Tag=FederationAndPICDefault, Tag=FederationOnly, Tag=NoFederationAndPIC"
		ExpectedValue    = 'Set-CsExternalAccessPolicy'
		ReturnedValue    = $findings
		Impact		     = "Informational"
		RiskRating	     = "Informational"
		PowerShellScript = ""
		References	     = @(@{ 'Name' = 'Manage external access (federation) - Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/manage-external-access' },
			@{ 'Name' = 'Use guest and external access to collaborate with people outside your organization'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/communicate-with-users-from-other-organizations' })
	}
}

Function Inspect-MSTeamsExternalAccessPolicy
{
	Try
	{
		
		Try
		{
			$rules = Get-CsExternalAccessPolicy
			
			$rules | Out-File -FilePath "$($path)\Teams-External-Access-Policies.txt"
			
			$endobject = Build-MSTeamsExternalAccessPolicy($rules.identity)
			return $endobject
		}
		Catch
		{
			Write-Warning -Message "Error processing request. Manual verification required."
			Return "Error processing request."
		}
		
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
return Inspect-MSTeamsExternalAccessPolicy


