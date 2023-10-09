# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Sharepoint
# Purpose: Ensure modern authentication for SharePoint applications is required
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMOff150($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMOff150"
		FindingName	     = "CIS MOff 1.5 - Admins Contain a License!"
		ProductFamily    = "Microsoft Office 365"
		RiskScore	     = "12"
		Description	     = "Ensuring administrative accounts are cloud-only, without applications assigned to them will reduce the attack surface of high privileged identities in your environment. In order to participate in Microsoft 365 security services such as Identity Protection, PIM and Conditional Access an administrative account will need a license attached to it. Ensure that the license used does not include any applications with potentially vulnerable services by using either Azure Premium P1 or Azure Premium P2 for the cloud-only account with administrator roles. In a hybrid environment, having separate accounts will help ensure that in the event of a breach in the cloud, that the breach does not affect the on-prem environment and vice-versa."
		Remediation	     = "You can review the list of accounts containing a license and change them in the Microsoft 365 Portal"
		PowerShellScript = ''
		DefaultValue	 = "No Licenses"
		ExpectedValue    = "No Licenses"
		ReturnedValue    = $findings
		Impact		     = "4"
		Likelihood	     = "3"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Add users and assign licenses at the same time'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/admin/add-users/add-users?view=o365-worldwide" })
	}
	return $inspectorobject
}

function Audit-CISMOff150
{
	try
	{
		$checkadminlicdata = @()
		$licensecollection = @()
		$admins = GetAdmins
		foreach ($admin in $admins)
		{
			$Licenses = Get-MgUserLicenseDetail -UserId $admin.Email | select SkuPartNumber
			foreach ($license in $Licenses)
			{
				$licensecollection += $license.SkuPartNumber
			}
			if ($licensecollection.Count -igt 0)
			{
				$checkadminlicdata += "User: $($admin.Email) has licence(s): $($licensecollection)"
				$licensecollection = @() #Resets licensecollection to null
			}
		}
		if ($checkadminlicdata.count -igt 0)
		{
			$checkadminlicdata | Format-Table -AutoSize | Out-File "$path\CISMOff150-AdminLicenses.txt"
			$endobject = Build-CISMOff150($checkadminlicdata)
			Return $endobject 
		}
		return $null
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}

function GetAdmins
{
	$AdminRoleHolders = [System.Collections.Generic.List[Object]]::new()
	[array]$AdminRoles = Get-MgDirectoryRole | Select-Object DisplayName, Id | Sort-Object DisplayName
	ForEach ($Role in $AdminRoles)
	{
		[array]$RoleMembers = Get-MgDirectoryRoleMember -DirectoryRoleId $Role.Id | ? { $_.AdditionalProperties."@odata.type" -eq "#microsoft.graph.user" }
		ForEach ($Member in $RoleMembers)
		{
			$UserDetails = Get-MgUser -UserId $Member.Id
			$ReportLine = [PSCustomObject] @{
				User   = $UserDetails.UserPrincipalName
				Id	   = $UserDetails.Id
				Role   = $Role.DisplayName
				RoleId = $Role.Id
			}
			$AdminRoleHolders.Add($ReportLine)
		}
	}
	$AdminRoleHolders = $AdminRoleHolders | Sort-Object User
	$Unique = $AdminRoleHolders | Sort-Object User -Unique
	
	# Create a slightly different report where each user has their assigned roles in one record
	$UniqueAdminRoleHolders = [System.Collections.Generic.List[Object]]::new()
	ForEach ($User in $Unique)
	{
		$Records = $AdminRoleHolders | Where-Object { $_.id -eq $User.Id }
		$AdminRoles = $Records.Role -join ", "
		$ReportLine = [PSCustomObject] @{
			Id    = $User.Id
			User  = $User.User
			Roles = $AdminRoles
		}
		$UniqueAdminRoleHolders.Add($ReportLine)
	}
	
	# Retrieve member accounts that are licensed
	[array]$Users = Get-MgUser -Filter "assignedLicenses/`$count ne 0 and userType eq 'Member'" -ConsistencyLevel eventual -CountVariable Records -All
	
	$UserRegistrationDetails = [System.Collections.Generic.List[Object]]::new()
	ForEach ($User in $Users)
	{
		#Write-Host ("Checking admin roles for {0}" -f $User.DisplayName)
		try
		{
			$Uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails/" + $User.Id
			$AccessMethodData = Invoke-MgGraphRequest -Uri $Uri -Method Get
			# Check if Admin
			$AdminAccount = $False; $AdminRolesHeld = $Null
			If ($user.id -in $UniqueAdminRoleHolders.Id)
			{
				$AdminAccount = $True
				$AdminRolesHeld = ($UniqueAdminRoleHolders | ? { $_.Id -eq $User.Id } | Select -ExpandProperty Roles)
			}
			$ReportLine = [PSCustomObject] @{
				User		 = $User.Displayname
				Id		     = $User.Id
				Email	     = $User.UserPrincipalName
				AdminAccount = $AdminAccount
				AdminRoles   = $AdminRolesHeld
			}
			$UserRegistrationDetails.Add($ReportLine)
		}
		catch
		{
			#Write-Warning "User is no Account: $($User.Displayname)"
		}
		
	} #End ForEach
	$EndObject = $UserRegistrationDetails | Where-Object { $_.AdminAccount -eq $True }
	return $EndObject
}

return Audit-CISMOff150