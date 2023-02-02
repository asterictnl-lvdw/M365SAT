# This is an CustomerLockbox Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft Exchange
# Purpose: Checks if the Customer Lockbox Feature is enabled or disabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling


function Build-CustomerLockbox($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0019"
		FindingName	     = "CustomerLockbox Feature is disabled"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "5.7"
		Description	     = "You should enable the Customer Lockbox feature. It requires Microsoft to get your approval for any datacenter operation that grants a Microsoft support engineer or other employee direct access to any of your data. Keeping it disabled could lead to data exfiltration by unauthorized Microsoft users when connecting to your computer."
		Remediation	     = "Use the PowerShell script to enable CustomerLockBox for your Exchange Tenant"
		PowerShellScript = 'Set-OrganizationConfig -CustomerLockBoxEnabled $true'
		DefaultValue	 = "False"
		ExpectedValue    = "True"
		ReturnedValue    = $findings.ToString()
		Impact		     = "Medium"
		RiskRating	     = "Medium"
		References	     = @(@{ 'Name' = 'CIS 3.1, 3.13, 13, 13.3'; 'URL' = "https://paper.bobylive.com/Security/CIS/CIS_Microsoft_365_Foundations_Benchmark_v1_4_0.pdf" })
	}
	return $inspectorobject
}

function Audit-CustomerLockbox
{
	try
	{
		$CustomerLockbox = Get-OrganizationConfig | Select-Object CustomerLockBoxEnabled
		
		if ($CustomerLockbox.CustomerLockBoxEnabled -match 'False')
		{
			$endobject = Build-CustomerLockbox('CustomerLockBoxEnabled: ' + $CustomerLockbox.CustomerLockBoxEnabled)
			return $endobject
		}
		return $null
	}
	catch
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
return Audit-CustomerLockbox