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

function Build-CSTM-Tms006($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Tms006"
		FindingName	     = "CSTM-Tms006 - Microsoft Teams Users Allowed to Preview Links in Messages"
		ProductFamily    = "Microsoft Teams"
		RiskScore	     = "6"
		Description	     = "Microsoft Teams by default enables and allows users to preview links in messages. Some organizations may wish to disable this functionality. Changing these settings may have unintended consequences. Speak with stakeholders and understand what functionality may be affected before disabling this access."
		Remediation	     = "This can be mitigated by navigating to the Teams admin center and turning off 'Allow' Previews under Messaging settings. This disables link previews globally. Alternatively, specific users and groups can be targeted by creating a new Messaging Policy and issuing a command in PowerShell"
		DefaultValue	 = "True"
		ExpectedValue    = "False"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "3"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		PowerShellScript = 'Set-CsTeamsMessagingPolicy -Identity "Policy Name" -AllowUrlPreviews $false'
		References	     = @(@{ 'Name' = 'How to turn off URL previews in Microsoft Teams?'; 'URL' = 'https://document360.com/blog/how-to-turn-off-url-previews-in-microsoft-teams/' },
			@{ 'Name' = 'MS Teams: 1 feature, 4 vulnerabilities'; 'URL' = 'https://positive.security/blog/ms-teams-1-feature-4-vulns' })
	}
}

Function Inspect-CSTM-Tms006
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
				$endobject = Build-CSTM-Tms006($results)
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

Return Inspect-CSTM-Tms006


