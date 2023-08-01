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

function Build-CSTM-Tms002($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Tms002"
		FindingName	     = "Microsoft Teams Users Allowed to Invite Anonymous Users"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "3.0"
		Description	     = "Microsoft Teams by default enables and allows anonymous users to join Teams meetings. This finding returns the users within the tenant that have the ability to invite anonymous users into the Teams environment. Some organizations may wish to disable this functionality, or restrict certain users, members, or roles from allowing anonymous users to join meetings. Changing these settings may have unintended consequences. Speak with shareholders and understand what functionality may be affected before disabling this access."
		Remediation	     = "This can be mitigated by navigating to the Teams admin center and turning off 'Anonymous users can join a meeting' under Meeting settings. This disables anonymous access globally. Alternatively, specific users and groups can be targeted by creating a new Meeting Policy and issuing the command in PowerShell."
		DefaultValue	 = "All users assigned to default Teams Meeting Policies"
		ExpectedValue    = "Not applicable"
		ReturnedValue    = $findings
		Impact		     = "Low"
		RiskRating	     = "Low"
		PowerShellScript = 'Set-CsTeamsMeetingPolicy -Identity "Policy Name" -AllowAnonymousUsersToJoinMeeting $false'
		References	     = @(@{ 'Name' = 'Manage external access (federation) - Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/manage-external-access' },
			@{ 'Name' = 'Block Point-to-Point file transfers'; 'URL' = 'https://docs.microsoft.com/en-us/skypeforbusiness/set-up-policies-in-your-organization/block-point-to-point-file-transfers' })
	}
}

Function Inspect-CSTM-Tms002
{
	Try
	{
		
		Try
		{
			$teamsPolicies = Get-CsTeamsMeetingPolicy
			$policies = @()
			$results = Get-CsOnlineUser | Where-Object { $null -eq $_.TeamsMeetingPolicy }
			
			Foreach ($policy in $teamsPolicies)
			{
				If ($policy.AllowAnonymousUsersToJoinMeeting -eq $true)
				{
					$policies += $policy.Identity
				}
			}
			
			If ($results.count -ne 0)
			{
				$endobject = Build-CSTM-Tms002($results.UserPrincipalName)
				Return $endobject
			}
		}
		catch
		{
			Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
			Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
			Return $null
		}
		
		Return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

Return Inspect-CSTM-Tms002


