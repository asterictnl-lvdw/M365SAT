# This is an SecureDefaults Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Checks if SecureDefaults are enabled within Azure Tenant
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SecureDefaults($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFAZAD0015"
		FindingName	     = "Microsoft Secure Defaults"
		ProductFamily    = "Microsoft Azure"
		CVS			     = "9.3"
		Description	     = "Microsoft Security Defaults are enabled on all tenants by default. Security Defaults configures and enforces a number of common security features. If more fine-grained security options are required, consider enabling Conditional Access policies. If Security Defaults are not enabled, ensure that other configurations are in place to safeguard your tenant and users."
		Remediation	     = "There is no such remediation. If Secure Defaults are not enabled, ensure that equivalent protections have been enforced. Please ensure that you follow Microsoft's best practices to ensure best security of your Azure tenant."
		PowerShellScript = ''
		DefaultValue	 = "None"
		ExpectedValue    = "None"
		ReturnedValue    = $findings
		Impact		     = "Critical"
		RiskRating	     = "Critical"
		References	     = @(@{ 'Name' = 'What are security defaults?'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/concept-fundamentals-security-defaults" },
			@{ 'Name' = 'Common Conditional Access Policies'; 'URL' = "https://docs.microsoft.com/en-us/azure/active-directory/conditional-access/concept-conditional-access-policy-common" })
	}
}


function Inspect-SecureDefaults
{
	Try
	{
		
		$conditionalAccess = Get-MgIdentityConditionalAccessPolicy #Get-AzureADMSConditionalAccessPolicy
		
		If (($conditionalAccess | Measure-Object).Count -eq 0)
		{
			$SDCreationDate = "October 22, 2019"
			$tenantCreationDate = (Get-MgOrganization).CreatedDateTime
			$secureDefault = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -Property IsEnabled | Select-Object IsEnabled
			$disabled = "Secure Defaults Not Enabled on this Tenant."
			$olderThan = "Tenant creation predates Secure Defaults, and as a result Secure Defaults is not enabled"
			If (($tenantCreationDate -lt $SDCreationDate) -and ($secureDefault.IsEnabled -eq $false))
			{
				$endobject = Build-SecureDefaults("$($secureDefault.IsEnabled): $olderThan")
				Return $endobject
			}
			elseif ($secureDefault.IsEnabled -eq $false)
			{
				$endobject = Build-SecureDefaults("$($secureDefault.IsEnabled): $disabled")
				Return $endobject
			}
		}
		Else
		{
			return $null
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
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname -failinglinenumber $failinglinenumber -failingline $failingline -pscommandpath $pscommandpath -positionmsg $pscommandpath -stacktrace $strace
		Write-Verbose "Errors written to log"
	}
	
}

Return Inspect-SecureDefaults


