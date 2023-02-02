# This is an MSTeamsAnonUsers Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Teams
# Purpose: Checks the MSTeams AnonymousPolicy if Anonymous members are invitable
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-MSTeamsAnonUsers($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID		      = "M365SATFMST0003"
		FindingName   = "Microsoft Teams Policies Allow Anonymous Members"
		ProductFamily = "Microsoft Teams"
		CVS		      = "3.0"
		Description   = "Microsoft Teams by default enables and allows  authenticated users to invite anonymous users to join Teams meetings. Some organizations may wish to disable this functionality, or restrict certain users, members, or roles from allowing anonymous users to join meetings. Changing these settings may have unintended consequences. Speak with shareholders and understand what functionality may be affected before disabling this access."
		Remediation   = "This can be mitigated by navigating to the Teams admin center and turning off 'Anonymous users can join a meeting' under Meeting settings. This disables anonymous access globally. Alternatively, specific users and groups can be targeted by creating a new Meeting Policy and issuing this command in PowerShell."
		DefaultValue  = "True for default policies= Global, Tag=AllOn, Tag=RestrictedAnonymousAccess, Tag=AllOff, Tag=RestrictedAnonymousNoRecording, Tag=Default, Tag=Kiosk"
		ExpectedValue = 'AllowAnonymousUsersToJoinMeeting: $false'
		ReturnedValue = $findings
		Impact	      = "Low"
		RiskRating    = "Low"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity "Default" -AllowAnonymousUsersToJoinMeeting $false'
		References    = @(@{ 'Name' = 'Manage external access (federation) - Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/manage-external-access' },
			@{ 'Name' = 'Block Point-to-Point file transfers'; 'URL' = 'https://docs.microsoft.com/en-us/skypeforbusiness/set-up-policies-in-your-organization/block-point-to-point-file-transfers' })
	}
}


Function Inspect-MSTeamsAnonUsers
{
	Try
	{
		
		Try
		{
			$teamsPolicies = Get-CsTeamsMeetingPolicy
			$policies = @()
			
			Foreach ($policy in $teamsPolicies)
			{
				If ($policy.AllowAnonymousUsersToJoinMeeting -eq $true)
				{
					$policies += $policy.Identity
				}
			}
			
			If (($policies | Measure-Object).count -ne 0)
			{
				$endobject = Build-MSTeamsAnonUsers($policies)
				Return $endobject
			}
		}
		Catch
		{
			Write-Warning -Message "Error processing request. Manual verification required."
			Return "Error processing request."
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

Return Inspect-MSTeamsAnonUsers


