# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Exchange
# Purpose: Ensure External OutLook Add-Ins cannot be installed Applications is Enabled
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMEx280($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx280"
		FindingName	     = "CIS MEx 2.8 - Users can Install Outlook Add-ins"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "10"
		Description	     = "Attackers commonly use vulnerable and custom-built add-ins to access data in user applications. While allowing users to install add-ins by themselves does allow them to easily acquire useful add-ins that integrate with Microsoft applications, it can represent a risk if not used and monitored carefully."
		Remediation	     = "Use the Tenable Reference and use the PowerShell template within the article."
		PowerShellScript = 'New-RoleAssignmentPolicy -Name "Example" -Roles $revisedRoles'
		DefaultValue	 = "Users can Install Outlook Add-Ins"
		ExpectedValue    = "Users cannot Install Outlook Add-Ins"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = '2.8 - Ensure users installing Outlook add-ins is not allowed'; 'URL' = "https://www.tenable.com/audits/items/CIS_Microsoft_365_v1.5.0_E3_Level_2.audit:51eaf859366d9e68cf92204846b01329" })
	}
	return $inspectorobject
}

function Audit-CISMEx280
{
	try
	{
		$InstallationOutlookAddInsData = @()
		
		$Policy = (Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Where-Object { $_.AssignedRoles -like "*Apps*" } } | Select-Object Identity, @{ Name = "AssignedRoles"; Expression = { Get-Mailbox | Select-Object -Unique RoleAssignmentPolicy | ForEach-Object { Get-RoleAssignmentPolicy -Identity $_.RoleAssignmentPolicy | Select-Object -ExpandProperty AssignedRoles | Where-Object { $_ -like "*Apps*" } } } })
		foreach ($AssignedRole in $Policy.AssignedRoles)
		{
			if ($AssignedRole -match "My Custom Apps")
			{
				$InstallationOutlookAddInsData += "Policy contains My Custom Apps!"
			}
			if ($AssignedRole -match "My Marketplace Apps")
			{
				$InstallationOutlookAddInsData += "Policy contains My Marketplace Apps!"
			}
			if ($AssignedRole -match "My ReadWriteMailboxApps")
			{
				$InstallationOutlookAddInsData += "Policy contains My ReadWriteMailboxApps!"
			}
		}
		if ($InstallationOutlookAddInsData.Count -igt -0)
		{
			$endobject = Build-CISMEx280($InstallationOutlookAddInsData)
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
return Audit-CISMEx280