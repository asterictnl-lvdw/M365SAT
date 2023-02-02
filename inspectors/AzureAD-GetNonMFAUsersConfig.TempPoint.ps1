# This is an AllUsersNonMFAStatus Inspector.

# Date: 22-11-2022
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Check if there are UserAccounts with no MFA enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

$path = @($OutPath)
function Build-AllUsersNonMFAStatus($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		FindingName		= "Non MFA - User Accounts Found!"
		ProductFamily	= "Microsoft Azure"
		CVS				= "8.2"
		Description		= "Some of the Admin Accounts are not compliant. Admins must have MFA enabled to not be targeted by password spraying attacks"
		Remediation		= "Enable MFA for all User Accounts!"
        PowerShellScript= "Set-MsolUser -UserPrincipalName {username} -StrongAuthenticationRequirements {strongauthentication}"
		DefaultValue	= "Not MFA Enabled"
		ExpectedValue	= "Number of Users (Non-Admins) without MFA: 0"
		ReturnedValue	= "Number of Users (Non-Admins) without MFA: $($Results.Count)"
		Impact			= "High"
		RiskRating 		= "High"
		References		= @(@{'Name'='Azure Identity Management and access control security best practices';'URL'='https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices'})
	}
    return $inspectorobject
}

Function Inspect-AllUsersNonMFAStatus {
Try {
    
$Users = Get-MsolUser -All
$NonMFAUsers = @()
$Results = @()

foreach ($User in $Users){
$Roles = Get-AzureADUserMembership -ObjectId $User.UserPrincipalName -All $true | Where-Object { $_.ObjectType -eq "Role"}
if (($Roles.Count -eq 0) -and ($User.StrongAuthenticationRequirements.State -eq $Null) -and ($_.StrongAuthenticationMethods.MethodType -eq $Null)){
$NonMFAUsers += $User
}
}


foreach ($User in $NonMFAUsers){
$Result = New-Object -TypeName PSObject -Property @{
 DisplayName = $User.DisplayName
 UserName = $User.UserPrincipalName
 Role = "User"
 Licensed = $User.IsLicensed
 BlockedFromSignIn = $User.BlockCredential
}
$Results += $Result
}

if ($Results.Count -ne 0){
$finalobject = Build-AllUsersNonMFAStatus($Results)
$Results | Format-Table -AutoSize | Out-File "$path\GetAllNonAdminsNonMFAStatus.txt"
return $finalobject
}

}
Catch {
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
Return Inspect-AllUsersNonMFAStatus