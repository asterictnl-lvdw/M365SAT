# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Azure v2.0.0
# Product Family: Microsoft Azure
# Purpose: Ensure multifactor authentication is enabled for all non-administrative users
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISMAz114($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMAz114"
		FindingName	     = "CIS MAz 1.1.4 - MultiFactor Authentication (MFA) is not enabled for all users non-administrative roles"
		ProductFamily    = "Microsoft Azure"
		RiskScore	     = "15"
		Description	     = "Multifactor authentication requires an individual to present a minimum of two separate forms of authentication before access is granted. Multifactor authentication provides additional assurance that the individual attempting to gain access is who they claim to be. With multifactor authentication, an attacker would need to compromise at least two different authentication mechanisms, increasing the difficulty of compromise and thus reducing the risk."
		Remediation	     = "It is recommended to enable MFA via Conditional Access if the license is applicable. There is no new script available. You can use the old MSOL Script if you want to enable per-user MFA"
		PowerShellScript = 'https://admindroid.sharepoint.com/:u:/s/external/EVzUDxQqxWdLj91v3mhAipsBt0GqNmUK5b4jFXPr181Svw?e=OOcfQn&isSPOFile=1'
		DefaultValue	 = "True for tenants >2019, False for tenants <2019"
		ExpectedValue    = "Number of User Accounts without MFA: 0"
		ReturnedValue    = "Number of User Accounts without MFA: $($findings.Count)"
		Impact		     = "3"
		Likelihood	     = "5"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = 'Microsoft Secure Score Series - 02 - Require MFA for non-administrative roles'; 'URL' = 'https://janbakker.tech/microsoft-secure-score-series-02-require-mfa-for-administrative-roles/' })
	}
	return $inspectorobject
}

function Audit-CISMAz114
{
	try
	{
		$users = ReportUsersNonMFA
		if ($users.Count -ne 0)
		{
			Build-CISMAz114($users.User)
		}
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
}

function ReportUsersNonMFA
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
		try
		{
			$Uri = "https://graph.microsoft.com/beta/reports/authenticationMethods/userRegistrationDetails/" + $User.Id
			$AccessMethodData = Invoke-MgGraphRequest -Uri $Uri -Method Get
			# Check if Admin
			$AdminAccount = $False; $AdminRolesHeld = $Null
			If ($user.id -in $UniqueAdminRoleHolders.Id)
			{
				$AdminAccount = $True
				$AdminRolesHeld = ($UniqueAdminRoleHolders | Where-Object { $_.Id -eq $User.Id } | Select-Object -ExpandProperty Roles)
			}
			$ReportLine = [PSCustomObject] @{
				User			 = $User.Displayname
				Id			     = $User.Id
				AdminAccount	 = $AdminAccount
				AdminRoles	     = $AdminRolesHeld
				MfaRegistered    = $AccessMethodData.isMfaRegistered
				defaultMfaMethod = $AccessMethodData.defaultMfaMethod
				isMfaCapable	 = $AccessMethodData.isMfaCapable
				Methods		     = $AccessMethodData.MethodsRegistered -join ", "
			}
			$UserRegistrationDetails.Add($ReportLine)
		}
		catch
		{
			#Write-Warning "User is no Account: $($User.Displayname)"
		}
		
	} #End ForEach
	
	[Array]$ProblemAdminAccounts = $UserRegistrationDetails | Where-Object { $_.AdminAccount -eq $False -and $_.MfaRegistered -eq $False }
	If ($ProblemAdminAccounts)
	{
		$ProblemAdminAccounts | Format-Table -AutoSize | Out-File "$path\GetAllNonAdminNonMFAStatus.txt"
	}
	
	return $ProblemAdminAccounts
}

return Audit-CISMAz114