# This is an AllAdminsNonMFAStatus Inspector.

# Date: 22-11-2022
# Version: 1.0
# Product Family: Microsoft Azure
# Purpose: Check if there are Admins with no MFA enabled
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

$path = @($OutPath)
$NonMFACount = 0
function Build-AllAdminsNonMFAStatus($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		FindingName		= "Non MFA - Admin Accounts Found!"
		ProductFamily	= "Microsoft Azure"
		CVS				= "8.2"
		Description		= "Some of the Admin Accounts are not compliant. Admins must have MFA enabled to not be targeted by password spraying attacks"
		Remediation		= "Enable MFA for all Administrator Accounts!"
        PowerShellScript= "Set-MsolUser -UserPrincipalName {username} -StrongAuthenticationRequirements {strongauthentication}" 
		DefaultValue	= "Not MFA Enabled"
		ExpectedValue	= "Number of Admin Accounts without MFA: 0"
		ReturnedValue	= "Number of Admin Accounts without MFA: $($NonMFACount.ToString())"
		Impact			= "High"
		RiskRating 		= "High"
		References		= @(@{'Name'='Microsoft Secure Score Series – 02 – Require MFA for administrative roles';'URL'='https://janbakker.tech/microsoft-secure-score-series-02-require-mfa-for-administrative-roles/'})
	}
    return $inspectorobject
}

Function Inspect-AllAdminsNonMFAStatus {
Try {

    $AllAdminsNonMFAStatusResults = @()

    # Get all licensed admins
$admins = Get-MsolRole | %{$role = $_.name; Get-MsolRoleMember -RoleObjectId $_.objectid} | Where-Object {$_.isLicensed -eq $true} | select @{Name="Role"; Expression = {$role}}, DisplayName, EmailAddress, ObjectId | Sort-Object -Property EmailAddress -Unique

# Get only the admins and check their MFA Status
  foreach ($admin in $admins) {
    $MsolUser = Get-MsolUser -ObjectId $admin.ObjectId | Sort-Object UserPrincipalName -ErrorAction Stop

    $MFAMethod = $MsolUser.StrongAuthenticationMethods | Where-Object {$_.IsDefault -eq $true} | Select-Object -ExpandProperty MethodType
    $Method = ""

    If (($MsolUser.StrongAuthenticationRequirements) -or ($MsolUser.StrongAuthenticationMethods)) {
        Switch ($MFAMethod) {
            "OneWaySMS" { $Method = "SMS token" }
            "TwoWayVoiceMobile" { $Method = "Phone call verification" }
            "PhoneAppOTP" { $Method = "Hardware token or authenticator app" }
            "PhoneAppNotification" { $Method = "Authenticator app" }
        }
      }
    
    # List only the user that don't have MFA enabled
        if (-not($MsolUser.StrongAuthenticationMethods) -or -not($MsolUser.StrongAuthenticationRequirements)) {

          $object = [PSCustomObject]@{
            DisplayName       = $MsolUser.DisplayName
            UserPrincipalName = $MsolUser.UserPrincipalName
            isAdmin           = if ($listAdmins -and ($admins.EmailAddress -match $MsolUser.UserPrincipalName)) {$true} else {"-"}
            MFAEnabled        = $false
            MFAType           = "-"
			MFAEnforced       = if ($MsolUser.StrongAuthenticationRequirements) {$true} else {"-"}
            "Email Verification" = if ($msoluser.StrongAuthenticationUserDetails.Email) {$msoluser.StrongAuthenticationUserDetails.Email} else {"-"}
            "Registered phone" = if ($msoluser.StrongAuthenticationUserDetails.PhoneNumber) {$msoluser.StrongAuthenticationUserDetails.PhoneNumber} else {"-"}
          }
            $NonMFACount++
          }
    
    $AllAdminsNonMFAStatusResults += $object
  }
    $finalobject = Build-AllAdminsNonMFAStatus($AllAdminsNonMFAStatusResults)
    $AllAdminsNonMFAStatusResults | Format-Table -AutoSize | Out-File "$path\GetAllAdminsNonMFAStatus.txt" 
    Return $finalobject

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

Return Inspect-AllAdminsNonMFAStatus