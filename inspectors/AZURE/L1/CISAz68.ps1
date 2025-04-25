#Requires -module Az.Accounts
# Benchmark: CIS Microsoft Azure v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISAz68
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz68"
        ID               = "6.8"
        Title            = "(L1) Ensure that a 'Custom banned password list' is set to 'Enforce'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "By default the custom bad password list is not 'Enabled'"
        ExpectedValue    = "True (List with passwords)"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enforcing a custom banned password list allows organizations to block commonly used or easily guessable passwords. This strengthens password security by preventing weak credentials that attackers could exploit."
        Impact           = "Increasing needed password complexity might increase overhead on administration of user accounts. Licensing requirement for Global Banned Password List and Custom Banned Password list requires Microsoft Entra ID P1 or P2. On-premises Active Directory Domain Services users that are not synchronized to Microsoft Entra ID also benefit from Microsoft Entra ID Password Protection based on existing licensing for synchronized users."
        Remediation      = "Manually enable 'Enforce Custom List' and configure banned passwords via the following link: `https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection`. No PowerShell script is available at this time."
        References       = @(
            @{ 'Name' = 'Combined password policy and check for weak passwords in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad-combined-policy' },
            @{ 'Name' = 'Eliminate bad passwords using Microsoft Entra Password Protection'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-password-ban-bad' },
            @{ 'Name' = 'Tutorial: Configure custom banned passwords for Microsoft Entra password protection'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-configure-custom-password-protection' }
        )
    }
    return $inspectorobject
}

function Audit-CISAz68
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$MethodsRequired = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/AuthenticationMethods/PasswordPolicy' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		# Validation
		if ($MethodsRequired.enforceCustomBannedPasswords -eq $false)
		{
			$AffectedOptions += "CustomBannedPasswords: $($MethodsRequired.enforceCustomBannedPasswords)"
		}
		if ($MethodsRequired.bannedPasswordCheckOnPremisesMode -eq 0)
		{
			$AffectedOptions += "PolicyMode: $($MethodsRequired.bannedPasswordCheckOnPremisesMode)"
		}
		if ($MethodsRequired.customBannedPasswords.count -ilt 0)
		{
			$AffectedOptions += "Number of Bad Passwords Listed: $($MethodsRequired.customBannedPasswords.count)"
		}
		if ($MethodsRequired.enableBannedPasswordCheckOnPremises -eq $false)
		{
			$AffectedOptions += "Password protection for Windows Server Active Directory: $($MethodsRequired.enableBannedPasswordCheckOnPremises)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$endobject = Build-CISAz68 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "5" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz68 -ReturnedValue ("Password Policy has no anomalies!") -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz68 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
		return $endobject
	}
}

function Invoke-MultiMicrosoftAPI
{
	param (
		#The whole URL to call
		[Parameter()]
		[String]$Url,
		#The Name of the Resource
		[Parameter()]
		[String]$Resource,
		[Parameter()]
		#Body if a POST or PUT
		[Object]$Body,
		[Parameter()]
		#Specify the HTTP Method you wish to use. Defaults to GET
		[ValidateSet("GET", "POST", "OPTIONS", "DELETE", "PUT")]
		[String]$Method = "GET"
	)
	
	try
	{
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	catch
	{
		Connect-AzAccount -ErrorAction Stop
		[Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]$Context = (Get-AzContext | Select-Object -first 1)
	}
	
	#Specify Resource
	$apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $Resource)
	
	# Creating the important header
	$header = [ordered]@{
		'Authorization' = 'Bearer ' + $apiToken.AccessToken.ToString()
		'Content-Type'  = 'application/json'
		'X-Requested-With' = 'XMLHttpRequest'
		'x-ms-client-request-id' = [guid]::NewGuid()
		'x-ms-correlation-id' = [guid]::NewGuid()
	}
	# URL Where PUT Request is being done. You can extract this from F12 
	
	$method = 'GET'
	
	#In Case your Method is PUT or POST to edit something. Change things here
	
	if ($method -eq 'PUT')
	{
		# Remediation Scripts HERE
		$contentpart1 = '{"restrictNonAdminUsers":false}'
		
		#Convert the content (DUMMY)
		$Body = $contentpart1
		
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'POST')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -Body $Body -ErrorAction Stop
	}
	elseif ($method -eq 'GET')
	{
		#Execute Request
		$Response = Invoke-RestMethod -Uri $Url -Headers $header -Method $Method -ErrorAction Stop
	}
	return $Response
}

return Audit-CISAz68