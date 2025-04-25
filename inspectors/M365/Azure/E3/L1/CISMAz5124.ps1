#Requires -module Az.Accounts
# Benchmark: CIS Microsoft 365 v4.0.0
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CISMAz5124
{
    param(
        $ReturnedValue,
        $Status,
        $RiskScore,
        $RiskRating
    )
    # Actual Inspector Object that will be returned. All object values are required to be filled in.
    $inspectorobject = New-Object PSObject -Property @{
        UUID             = "CISMAz5124"
        ID               = "5.1.2.4"
        Title            = "(L1) Ensure access to the Entra admin center is restricted"
        ProductFamily    = "Microsoft Azure"
        DefaultValue     = "restrictNonAdminUsers: False"
        ExpectedValue    = "restrictNonAdminUsers: True"
        ReturnedValue    = $ReturnedValue
        Status           = $Status
        RiskScore        = $RiskScore
        RiskRating       = $RiskRating
        Description      = "The Azure AD administrative (AAD) portal contains sensitive data and permission settings based on user roles. If access is not restricted, end users may unintentionally modify configurations, leading to increased administrative overhead. Moreover, a compromised user account could be leveraged by attackers to gather sensitive information and escalate privileges."
        Impact           = "Unrestricted access to the Azure AD portal can lead to accidental configuration changes and security vulnerabilities due to potential misuse by unauthorized or compromised accounts."
        Remediation 	 = 'https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings/menuId/UserSettings'
        References       = @(
            @{ 'Name' = 'Restrict member users default permissions'; 'URL' = 'https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions#restrict-member-users-default-permissions' }
        )
    }
    return $inspectorobject
}

function Audit-CISMAz5124
{
	try
	{
		$AffectedOptions = @()
		# Actual Script
		$RestrictNonAdmins = Invoke-MultiMicrosoftAPI -Url 'https://main.iam.ad.ext.azure.com/api/Directories/Properties' -Resource "74658136-14ec-4630-ad9b-26e160ff0fc6" -Method 'GET'
		
		# Validation
		if ($RestrictNonAdmins.restrictNonAdminUsers -ne $True)
		{
			$AffectedOptions += "restrictNonAdminUsers: $($RestrictNonAdmins.restrictNonAdminUsers)"
		}
		if ($AffectedOptions.count -igt 0)
		{
			$RestrictNonAdmins | Format-Table -AutoSize | Out-File "$path\CISMAz5124-NonAdminUserRestrictionSettings.txt"
			$endobject = Build-CISMAz5124 -ReturnedValue ($AffectedOptions) -Status "FAIL" -RiskScore "10" -RiskRating "High"
			return $endobject
		}
		else
		{
			$endobject = Build-CISMAz5124 -ReturnedValue "restrictNonAdminUsers: $($RestrictNonAdmins.restrictNonAdminUsers)" -Status "PASS" -RiskScore "0" -RiskRating "None"
			Return $endobject
		}
		return $null
	}
	catch
	{
		$endobject = Build-CISMAz5124 -ReturnedValue "UNKNOWN" -Status "UNKNOWN" -RiskScore "0" -RiskRating "UNKNOWN"
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
return Audit-CISMAz5124