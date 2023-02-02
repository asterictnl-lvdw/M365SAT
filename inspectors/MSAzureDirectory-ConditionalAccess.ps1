# This is an CAPolicies Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Conditional Access is enabled within Azure and correctly configured
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-CAPolicies($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0005"
		FindingName	     = "Incorrect Conditional Access Policies / No Conditional Access Policies Enabled"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "4.6"
		Description	     = "Conditional Access Policy review. If False was returned, no Conditional Access policies were found and Secure Defaults have been disabled. This leaves the Tenant extremely vulnerable to various attacks. If True was returned, existing Conditional Access Policies will be exported for review."
		Remediation	     = "If False was returned, consider creating Conditional Access policies or re-enabling Secure Defaults. For recommended configuration, please use the references to configure Conditional Access Policies within your Azure Tenant."
		PowerShellScript = 'New-AzureADMSConditionalAccessPolicy'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		References	     = @(@{ 'Name' = 'Raising the Baseline Security for all Organizations in the World'; 'URL' = "https://techcommunity.microsoft.com/t5/azure-active-directory-identity/raising-the-baseline-security-for-all-organizations-in-the-world/ba-p/3299048" },
			@{ 'Name' = 'Create Conditional Access Policies using PowerShell'; 'URL' = "https://helloitsliam.com/2021/09/23/create-conditional-access-policies-using-powershell/" },
			@{ 'Name' = 'Create a Azure AD Conditional Access Policy using PowerShell'; 'URL' = "https://ourcloudnetwork.com/create-a-azure-ad-conditional-access-policy-using-powershell/" })
	}
}

function Inspect-CAPolicies
{
	Try
	{
		$tenantLicense = (Get-MgSubscribedSku).ServicePlans
		
		If ($tenantLicense.ServicePlanName -match "AAD_PREMIUM*")
		{
			
			$secureDefault = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -Property IsEnabled | Select-Object IsEnabled
			$conditionalAccess = Get-MgIdentityConditionalAccessPolicy
			
			If ($secureDefault.IsEnabled -eq $true)
			{
				Return $null
			}
			ElseIf (($secureDefault.IsEnabled -eq $false) -and ($conditionalAccess.count -eq 0))
			{
				$endobject = Build-CAPolicies($false)
				Return $endobject

			}
			else
			{
				$path = New-Item -ItemType Directory -Force -Path "$($path)\ConditionalAccess"
				
				Foreach ($policy in $conditionalAccess)
				{
					
					$name = $policy.DisplayName
					
					$pattern = '[\\\[\]\{\}/():;\*\"]'
					
					$name = $name -replace $pattern, '-'
					
					$result = New-Object psobject
					$result | Add-Member -MemberType NoteProperty -name Name -Value $policy.DisplayName -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name State -Value $policy.State -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedApps -Value $policy.conditions.applications.includeapplications -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name ExcludedApps -Value $policy.conditions.applications.excludeapplications -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedUserActions -Value $policy.conditions.includeuseractions -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedProtectionLevels -Value $policy.conditions.includeprotectionlevels -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedUsers -Value $policy.conditions.users.includeusers -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name ExcludedUsers -Value $policy.conditions.users.excludeusers -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedGroups -Value $policy.conditions.users.includegroups -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name ExcludedGroups -Value $policy.conditions.users.excludegroups -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedRoles -Value $policy.conditions.users.includeroles -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name ExcludedRoles -Value $policy.conditions.users.excluderoles -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedPlatforms -Value $policy.conditions.platforms.includeplatforms -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name ExcludedPlatforms -Value $policy.conditions.platforms.excludeplatforms -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedLocations -Value $policy.conditions.locations.includelocations -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name ExcludedLocations -Value $policy.conditions.locations.excludelocations -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name IncludedSignInRisk -Value $policy.conditions.SignInRiskLevels -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name ClientAppTypes -Value $policy.conditions.ClientAppTypes -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name GrantConditions -Value $policy.grantcontrols.builtincontrols -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name ApplicationRestrictions -Value $policy.sessioncontrols.ApplicationEnforcedRestrictions -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name CloudAppSecurity -Value $policy.sessioncontrols.CloudAppSecurity -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name SessionLifetime -Value $policy.sessioncontrols.signinfrequency -ErrorAction SilentlyContinue
					$result | Add-Member -MemberType NoteProperty -name PersistentBrowser -Value $policy.sessioncontrols.PersistentBrowser -ErrorAction SilentlyContinue
					
					
					$result | Out-File -FilePath "$($path)\$($name)_Policy.txt"
					$endobject = Build-CAPolicies($result)
					Return $endobject
				}
			}
		}
		Else
		{
			$endobject = Build-CAPolicies("Tenant is not licensed for Conditional Access.")
			Return $endobject
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

return Inspect-CAPolicies


