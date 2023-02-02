# This is an MSTeamsLinkPreview Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Teams
# Purpose: Checks the MSTeams Link Preview is activated with links. 
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-MSTeamsLinkPreview($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMST0007"
		FindingName	     = "Microsoft Teams Users Allowed to Preview Links in Messages"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "3.0"
		Description	     = "Microsoft Teams by default enables and allows users to preview links in messages. Some organizations may wish to disable this functionality. Changing these settings may have unintended consequences. Speak with stakeholders and understand what functionality may be affected before disabling this access."
		Remediation	     = "This can be mitigated by navigating to the Teams admin center and turning off 'Allow' Previews under Messaging settings. This disables link previews globally. Alternatively, specific users and groups can be targeted by creating a new Messaging Policy and issuing a command in PowerShell"
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "Low"
		RiskRating	     = "Low"
		PowerShellScript = 'Set-CsTeamsMessagingPolicy -Identity "Policy Name" -AllowUrlPreviews $false'
		References	     = @(@{ 'Name' = 'How to turn off URL previews in Microsoft Teams?'; 'URL' = 'https://document360.com/blog/how-to-turn-off-url-previews-in-microsoft-teams/' },
			@{ 'Name' = 'MS Teams: 1 feature, 4 vulnerabilities'; 'URL' = 'https://positive.security/blog/ms-teams-1-feature-4-vulns' })
	}
}

Function Inspect-MSTeamsLinkPreview
{
	Try
	{
		
		Try
		{
			$users = Get-CsOnlineUser
			
			$teamsPolicies = Get-CsTeamsMessagingPolicy | Where-Object { $_.AllowUrlPreviews -eq $true }
			
			$results = @()
			
			Foreach ($user in $users)
			{
				If ((($user.TeamsMessagingPolicy.Name).length -lt 1) -or ($teamsPolicies -match $user.TeamsMessagingPolicy.Name))
				{
					$results += $user.UserPrincipalName
				}
			}
			
			If ($results.count -ne 0)
			{
				$endobject = Build-MSTeamsLinkPreview($results)
				return $endobject
			}
			else
			{
				return $null
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

Return Inspect-MSTeamsLinkPreview


