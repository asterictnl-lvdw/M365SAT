# This is an MSTeamsConsumerSettings Inspector.

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

function Build-MSTeamsConsumerSettings($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID		      = "M365SATFMST0004"
		FindingName	     = "Microsoft Teams Consumer Communication Policies"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "6.5"
		Description	     = "Microsoft Teams External Access Policies allow communication with Teams users not managed by an organization."
		Remediation	     = "Review Microsoft Teams External Access Policies and validate that all results are expected and no conflicting rules are in place."
		DefaultValue	 = "No restrictions are in place for communication with public Skype or Teams users"
		ExpectedValue    = "Not applicable"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		PowerShellScript = 'Not Available'
		References    = @(@{ 'Name' = 'Manage external access (federation) - Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/manage-external-access' },
			@{ 'Name' = 'Use guest and external access to collaborate with people outside your organization'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/communicate-with-users-from-other-organizations' })
	}
}



Function Inspect-MSTeamsConsumerSettings {
Try {

	Try {
        $configuration = Get-CsTenantFederationConfiguration

        $result = $null

            If (($configuration.AllowTeamsConsumer -eq $true) -and ($configuration.AllowTeamsConsumerInbound -eq $true) -and ($configuration.AllowPublicUsers -eq $true)){
                $result = "No restrictions are in place for communication with public Skype or Teams users."
                }

            ElseIf (($configuration.AllowTeamsConsumerInbound -eq $true) -and ($configuration.AllowTeamsConsumer -eq $true)){
                $result = "Public Teams users can initiate unsolicited communication to internal recipients."
                }
        
            ElseIf (($configuration.AllowTeamsConsumer -eq $true) -and ($configuration.AllowTeamsConsumerInbound -eq $false)){
                $result = "Users are allowed to initiate communication with public Teams users."
               }

            ElseIf (($configuration.AllowPublicUsers -eq $true) -and ($configuration.AllowTeamsConsumer -eq $false)){
                $result = "No restrictions are in place for communication with public Skype users."
			}
			Else
			{
				return $null
			}
			$endobject = Build-MSTeamsConsumerSettings($result)
			Return $endobject

        }
	Catch {
        Write-Warning -Message "Error processing request. Manual verification required."
        Return "Error processing request."
        }

}
Catch {
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
return Inspect-MSTeamsConsumerSettings


