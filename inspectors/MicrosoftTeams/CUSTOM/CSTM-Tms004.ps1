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

function Build-CSTM-Tms004($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Tms004"
		FindingName	     = "CSTM-Tms004 - Microsoft Teams Consumer Communication Policies"
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
		References	     = @(@{ 'Name' = 'Manage external access (federation) - Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/manage-external-access' },
			@{ 'Name' = 'Use guest and external access to collaborate with people outside your organization'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/communicate-with-users-from-other-organizations' })
	}
}



Function Inspect-CSTM-Tms004
{
	Try
	{
		
		Try
		{
			$configuration = Get-CsTenantFederationConfiguration
			
			$result = $null
			
			If (($configuration.AllowTeamsConsumer -eq $true) -and ($configuration.AllowTeamsConsumerInbound -eq $true) -and ($configuration.AllowPublicUsers -eq $true))
			{
				$result = "No restrictions are in place for communication with public Skype or Teams users."
			}
			
			ElseIf (($configuration.AllowTeamsConsumerInbound -eq $true) -and ($configuration.AllowTeamsConsumer -eq $true))
			{
				$result = "Public Teams users can initiate unsolicited communication to internal recipients."
			}
			
			ElseIf (($configuration.AllowTeamsConsumer -eq $true) -and ($configuration.AllowTeamsConsumerInbound -eq $false))
			{
				$result = "Users are allowed to initiate communication with public Teams users."
			}
			
			ElseIf (($configuration.AllowPublicUsers -eq $true) -and ($configuration.AllowTeamsConsumer -eq $false))
			{
				$result = "No restrictions are in place for communication with public Skype users."
			}
			Else
			{
				return $null
			}
			$endobject = Build-CSTM-Tms004($result)
			Return $endobject
			
		}
		catch
		{
			Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
			Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}
return Inspect-CSTM-Tms004


