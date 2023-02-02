# This is an SPOUnmanagedDevicesBlock Inspector.

# Date: 25-1-2023
# Version: 1.0
# Product Family: Microsoft SharePoint
# Purpose: Checks the SharePoint Unmanaged Devices Block
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Determine OutPath
$path = @($OutPath)

function Build-SPOUnmanagedDevicesBlock($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMSP0009"
		FindingName	     = "No AllowList set up and Unmanaged Device Restriction Enabled"
		ProductFamily    = "Microsoft Sharepoint"
		CVS			     = "8.4"
		Description	     = 'Unmanaged devices pose a risk, since their security cannot be verified. Allowing users to sync data to these devices, takes that data out of the control of the organization. This increases the risk of the data either being intentionally or accidentally leaked.'
		Remediation	     = 'Run Get-ADDomain to get the Device IDs and run the PowerShell Command and fill in the GUIDs with the devices you want to block:'
		DefaultValue	 = "False <br /> False"
		ExpectedValue    = "True <br /> True"
		ReturnedValue    = $findings
		Impact		     = "High"
		RiskRating	     = "High"
		PowerShellScript = 'Set-SPOTenantSyncClientRestriction -Enable -DomainGuids "GUID1; GUID2" -BlockMacSync=$true '
		References	     = @(@{ 'Name' = 'Reference - Set-SPOTenant'; 'URL' = 'https://docs.microsoft.com/en-us/powershell/module/sharepoint-online/set-spotenant?view=sharepoint-ps' })
	}
}


function Audit-SPOUnmanagedDevicesBlock
	{
		try
		{
			$SPOUnmanagedDevicesBlockData = @()
			$SPOUnmanagedDevicesBlock = Get-SPOTenantSyncClientRestriction | select TenantRestrictionEnabled, AllowedDomainList, BlockMacSync
			if ($SPOUnmanagedDevicesBlock.TenantRestrictionEnabled -match 'False' -or $SPOUnmanagedDevicesBlock.BlockMacSync -match 'False')
			{
				$SPOUnmanagedDevicesBlockData += " TenantRestrictionEnabled: " + $SPOUnmanagedDevicesBlock.TenantRestrictionEnabled
				$SPOUnmanagedDevicesBlockData += "`n AllowedDomainList: " + $SPOUnmanagedDevicesBlock.AllowedDomainList
				$SPOUnmanagedDevicesBlockData += "`n BlockMacSync: " + $SPOUnmanagedDevicesBlock.BlockMacSync
				$endobject = Build-SPOUnmanagedDevicesBlock($SPOUnmanagedDevicesBlockData)
				return $endobject
			}
			return $null
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
	return Audit-SPOUnmanagedDevicesBlock