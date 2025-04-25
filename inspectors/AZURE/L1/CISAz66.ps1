#Requires -module Az.Accounts
# Benchmark: CIS Microsoft Azure v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)


function Build-CISAz66
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISAz66"
        ID               = "6.6"
        Title            = "(L1) Ensure that account 'Lockout Threshold' is less than or equal to '10'"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "10"
        ExpectedValue    = "≤10"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "Account lockout is a method of protecting against brute-force and password spray attacks. Once the lockout threshold has been exceeded, the account enters a locked-out state which prevents all login attempts for a variable duration. The lockout in combination with a reasonable duration reduces the total number of failed login attempts that a malicious actor can execute in a given period of time."
        Impact           = "If account lockout threshold is set too low (less than 3), users may experience frequent lockout events and the resulting security alerts may contribute to alert fatigue. If account lockout threshold is set too high (more than 10), malicious actors can programmatically execute more password attempts in a given period of time."
        Remediation      = "Manually change the lockout threshold value in the Azure Portal via the following link: `https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection`. Currently, there is no PowerShell script available to automate this change."
        References       = @(
            @{ 'Name' = 'Manage Microsoft Entra smart lockout values'; 'URL' = 'https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout#manage-microsoft-entra-smart-lockout-values' }
        )
    }
    return $inspectorobject
}


function Audit-CISAz66
{
	try
	{
		# Actual Script
		$MethodsRequired = Invoke-MultiMicrosoftAPI -Url "https://main.iam.ad.ext.azure.com/api/AuthenticationMethods/PasswordPolicy" -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		# Validation
		if ($MethodsRequired.lockoutThreshold -igt 10)
		{
			$endobject = Build-CISAz66 -ReturnedValue ($MethodsRequired.lockoutThreshold) -Status "FAIL" -RiskScore "3" -RiskRating "Low"
			return $endobject
		}
		else
		{
			$endobject = Build-CISAz66 -ReturnedValue ($MethodsRequired.lockoutThreshold) -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISAz66 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
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
return Audit-CISAz66

