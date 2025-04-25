#Requires -module Az.Accounts
# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5241
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5241"
        ID               = "5.2.4.1"
        Title            = "(L1) Ensure 'Self service password reset enabled' is set to 'All'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "0"
        ExpectedValue    = "2"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Enabling self-service password reset (SSPR) for all users ensures that users can reset their passwords without helpdesk intervention. This also improves security by blocking common, easily guessable passwords during the reset process."
        Impact           = "Users will be required to provide additional contact information to enroll in self-service password reset. Additionally, minor user education may be required for users that are used to calling a help desk for assistance with password resets."
        Remediation 	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/Properties'
        References       = @(
            @{ 'Name' = 'Let users reset their own passwords'; 'URL' = 'https://learn.microsoft.com/en-us/microsoft-365/admin/add-users/let-users-reset-passwords?view=o365-worldwide' },
            @{ 'Name' = 'Tutorial: Enable users to unlock their account or reset passwords using Microsoft Entra self-service password reset'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/tutorial-enable-sspr' },
            @{ 'Name' = 'Enable combined security information registration in Microsoft Entra ID'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-registration-mfa-sspr-combined' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5241
{
	try
	{
		# Actual Script
		$SSPRSetting = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/PasswordReset/PasswordResetPolicies?getPasswordResetEnabledGroup=true' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		# Validation
		if ($SSPRSetting.enablementType -ne 2)
		{
			$SSPRSetting | Format-Table -AutoSize | Out-File "$path\CISMAz5241-SSPRSettings.txt"
			$endobject = Build-CISMAz5241 -ReturnedValue ($SSPRSetting.enablementType) -Status "FAIL" -RiskScore "9" -RiskRating "Medium"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5241 -ReturnedValue ($SSPRSetting.enablementType) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5241 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
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
return Audit-CISMAz5241