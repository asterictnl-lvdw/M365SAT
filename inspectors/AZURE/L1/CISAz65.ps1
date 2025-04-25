#Requires -module Az.Accounts
# Benchmark: CIS Microsoft Azure v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz65
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz65"
        ID               = "6.5"
        Title            = "(L1) Ensure That 'Number of methods required to reset' is set to '2'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "2"
        ExpectedValue    = "2"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "A Self-service Password Reset (SSPR) through Azure Multi-factor Authentication (MFA) ensures the user's identity is confirmed using two separate methods of identification. With multiple methods set, an attacker would have to compromise both methods before they could maliciously reset a user's password."
        Impact           = "There may be administrative overhead, as users who lose access to their secondary authentication methods will need an administrator with permissions to remove it. There will also need to be organization-wide security policies and training to teach administrators to verify the identity of the requesting user so that social engineering cannot render this setting useless."
        Remediation      = "Manually change the value from 1 to 2 in the Azure Portal via the following link: `https://portal.azure.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/AuthenticationMethods`. Currently, there is no PowerShell script available to automate this change."
        References       = @(
            @{ 'Name' = 'Tutorial: Enable users to unlock their account or reset passwords using Microsoft Entra self-service password reset'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr' },
            @{ 'Name' = 'Combined security information registration for Microsoft Entra overview'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-registration-mfa-sspr-combined' },
            @{ 'Name' = 'IM-6: Use strong authentication controls'; 'URL' = 'https://learn.microsoft.com/en-us/security/benchmark/azure/security-controls-v3-identity-management#im-6-use-strong-authentication-controls' },
            @{ 'Name' = 'Password reset registration'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/passwords-faq#password-reset-registration' },
            @{ 'Name' = 'Plan a Microsoft Entra self-service password reset deployment'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-sspr-deployment' },
            @{ 'Name' = 'What authentication and verification methods are available in Microsoft Entra ID?'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods' }
        )
    }
    return $inspectorobject
}


function Audit-CISAz65
{
	try
	{
		# Actual Script
		$MethodsRequired = Invoke-MultiMicrosoftAPI -Url "https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=false" -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		# Validation
		if ($MethodsRequired.numberOfAuthenticationMethodsRequired -ne 2)
		{
			$endobject = Build-CISAz65 -ReturnedValue ($MethodsRequired.numberOfAuthenticationMethodsRequired) -Status "FAIL" -RiskScore "3" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz65 -ReturnedValue ($MethodsRequired.numberOfAuthenticationMethodsRequired) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz65 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
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
return Audit-CISAz65

