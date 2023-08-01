# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Sharepoint
# Purpose: Ensure Idle Browser SignOut is correctly configured
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Sp005($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Sp005"
		FindingName	     = "CSTM-Sp005 - No AllowList set up and Unmanaged Device Restriction Enabled"
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


function Audit-CSTM-Sp005
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
			$endobject = Build-CSTM-Sp005($SPOUnmanagedDevicesBlockData)
			return $endobject
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}
return Audit-CSTM-Sp005