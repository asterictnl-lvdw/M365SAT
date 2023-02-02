# This is an AZPSAssignment Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if Service Principals are configured for the tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

function Build-AZPSAssignment($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID		      = "M365SATFAZAD0010"
		FindingName   = "Azure PowerShell Service Principal Assignment Not Enforced"
		ProductFamily = "Microsoft Azure"
		CVS		      = "9.9"
		Description   = "Dangerous default configuration settings were found in the tenant. By default, Azure tenants allow all users to access the Azure Active Directory and Microsoft Graph PowerShell Modules. This allows any authenticated user or guest the ability to abuse Dangerous Default Permissions, as well as enumerate the entire tenant. Service Principals allow only assigned users to have these permissions instead of everyone."
		Remediation   = "These permissions can be mitigated by creating and assigning Service Principals for the applications using the instructions in the linked blog post and setting the AppRoleAssignmentRequired attribute to $true for each Service Principal."
		PowerShellScript = 'Please look at the recommendation paragraph within the References'
		DefaultValue  = "None"
		ExpectedValue = "Assigned Users, Groups, or Directory Roles"
		ReturnedValue = $findings
		Impact	      = "Critical"
		RiskRating    = "Critical"
		References    = @(@{ 'Name' = 'Azure AD Default Configuration Blunders'; 'URL' = "https://medium.com/soteria-security/azure-ad-default-configuration-blunders-c7abddeae56" })
	}
}


Function Inspect-AZPSAssignment
{
	Try
	{
		
		$appIds = @("1b730954-1685-4b74-9bfd-dac224a7b894", "14d82eec-204b-4c2f-b7e8-296a70dab67e")
		
		$void = "No Service Principals Found"
		
		$aad = $false
		
		$graph = $false
		
		#Check for Service Prinicpals
		Foreach ($appId in $appIds)
		{
			Try
			{
				$sp = Get-MgServicePrincipal -Filter "appId eq '$appId'"
				$app = Get-MgServicePrincipal -ServicePrincipalId $sp.Id
			}
			Catch
			{
				$endobject = Build-AZPSAssignment($void)
				Return $endobject 
			}
			
			If ($null -ne $app)
			{
				if ($app.appID -eq '1b730954-1685-4b74-9bfd-dac224a7b894' -and $app.AppRoleAssignmentRequired -eq $true)
				{
					$aad = $true
				}
				elseif ($app.appID -eq '14d82eec-204b-4c2f-b7e8-296a70dab67e' -and $app.AppRoleAssignmentRequired -eq $true)
				{
					$graph = $true
				}
			}
		}
		
		$appAAD = "Azure Active Directory PowerShell is not assigned"
		
		$appGraph = "Microsoft Graph PowerShell is not assigned"
		
		$both = "Neither Azure Active Directory PowerShell or Microsoft Graph PowerShell are assigned"
		
		If ($aad -eq $false -and $graph -eq $false)
		{ 
			$endobject = Build-AZPSAssignment($both)
			Return $endobject
		}
		elseif ($aad -eq $false -and $graph -eq $true)
		{
			$endobject = Build-AZPSAssignment($appAAD)
			Return $endobject
		}
		elseif ($aad -eq $true -and $graph -eq $false)
		{
			$endobject = Build-AZPSAssignment($appGraph)
			Return $endobject
		}
		else
		{
			Return $null
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

Return Inspect-AZPSAssignment


