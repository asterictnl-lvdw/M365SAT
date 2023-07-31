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

function Build-CSTM-Tms001($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Tms001"
		FindingName	     = "CSTM-Tms001 - Microsoft Teams External Domain Communication Policies"
		ProductFamily    = "Microsoft Teams"
		CVS			     = "6.5"
		Description	     = "Microsoft Teams can communicate with external domains. This could lead to data exfiltration as external domains could include personal accounts. Please review this policy and ensure no malicious domains have access to join the Teams tenant."
		Remediation	     = "Review Microsoft Teams External Access Policies and validate that all results are expected, and no conflicting rules are in place."
		DefaultValue	 = "All Domains Allowed"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		PowerShellScript = ''
		References	     = @(@{ 'Name' = 'Manage external access (federation) - Microsoft Teams'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/manage-external-access' },
			@{ 'Name' = 'Use guest and external access to collaborate with people outside your organization'; 'URL' = 'https://docs.microsoft.com/en-us/microsoftteams/communicate-with-users-from-other-organizations' })
	}
}


Function Inspect-CSTM-Tms001
{
	Try
	{
		
		Try
		{
			$configuration = Get-CsTenantFederationConfiguration
			$domains = @()
			
			If (($configuration.AllowedDomains -like "*AllowAllKnownDomains*") -and ($configuration.AllowFederatedUsers -eq $true))
			{
				$domains += "All Domains Allowed"
			}
			
			If (($configuration.AllowedDomains -like "*AllowAllKnownDomains*") -and ($configuration.AllowFederatedUsers -eq $false))
			{
				$domains += "All External Domains Blocked"
			}
			
			If ($configuration.AllowedDomains -Like "Domain=*")
			{
				$domains += "Allowed domains: $($configuration.AllowedDomains)"
			}
			
			If ($configuration.BlockedDomains)
			{
				$domains += "Blocked domains: $($configuration.BlockedDomains)"
			}
			If ($domains.Count -ne 0)
			{
				$endobject = Build-CSTM-Tms001($permissions.AllowedToCreateApps)
				Return $endobject
			}
			else
			{
				Return $null
			}
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
return Inspect-CSTM-Tms001


