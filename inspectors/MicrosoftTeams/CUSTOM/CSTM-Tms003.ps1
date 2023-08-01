# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Teams
# Purpose: Ensure External Domain Communication Policies are existing
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Tms003($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Tms003"
		FindingName   = "CSTM-Tms003 - Microsoft Teams Policies Allow Anonymous Members"
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


Function Inspect-CSTM-Tms003
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
				$endobject = Build-CSTM-Tms003($policies)
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
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

Return Inspect-CSTM-Tms003


