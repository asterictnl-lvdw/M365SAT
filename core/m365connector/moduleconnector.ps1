<# Initiates connections to modules #>
<# Due to issues with Powershell 7 you need to additionally import modules in compatibility mode in order to make them work correctly #>
function Invoke-M365SATConnections($OrgName)
{

<# Ensures all Connections are established before executing the program #>
<# Add Commands to connect to respective Module here #>
	if (-not [string]::IsNullOrEmpty($Username) -and -not [string]::IsNullOrEmpty($Password))
	{
		# Use compatibility mode for MSonline, AzureAD, SharePointOnline,
		if ($PSVersionTable.PSVersion.Major -igt 5)
		{
			Import-Module MSOnline -UseWindowsPowershell
			Import-Module AzureADPreview -UseWindowsPowershell
			Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowershell
			Import-Module Microsoft.Graph.Authentication -UseWindowsPowershell
			Import-Module Microsoft.Graph.Intune -UseWindowsPowershell -DisableNameChecking -ErrorAction SilentlyContinue
			Import-Module PnP.PowerShell -UseWindowsPowershell -DisableNameChecking -ErrorAction SilentlyContinue
		}
		#Authentication Username + Password 
		#Store Credentials in Variable
		try
		{
			$SecuredPassword = ConvertTo-SecureString -AsPlainText $Password -Force
			$Credential = New-Object System.Management.Automation.PSCredential $UserName, $SecuredPassword
		}
		catch { Write-Error "Could Not Convert Credentials!" }
		$commands = @('$Team = Connect-MicrosoftTeams -Credential $Credential -ErrorAction Stop', 'Connect-AzAccount -Credential $Credential -ErrorAction Stop | Out-Null',
			'Connect-MsolService -Credential $Credential -ErrorAction Stop', 'Connect-AzureAD -Credential $Credential -ErrorAction Stop | Out-Null',
			'Connect-ExchangeOnline -Credential $Credential -ShowBanner:$false -ErrorAction Stop', 'Connect-SPOService -Url "https://$OrgName-admin.sharepoint.com" -Credential $Credential -ErrorAction Stop',
			'Connect-MSGraph -AdminConsent -ErrorAction Stop | Out-Null', 'Connect-PnPOnline -ErrorAction Stop -Url "https://$OrgName.sharepoint.com" -Credentials $Credential',
			'$MSGraph = Connect-MgGraph -ErrorAction Stop -Scopes "AuditLog.Read.All","Policy.Read.All","Directory.Read.All","IdentityProvider.Read.All","Organization.Read.All","Securityevents.Read.All","ThreatIndicators.Read.All","SecurityActions.Read.All","User.Read.All","UserAuthenticationMethod.Read.All","MailboxSettings.Read"',
			'Connect-IPPSSession -Credential $Credential -WarningAction SilentlyContinue -ErrorAction Stop')
		
	}
	elseif (-not [string]::IsNullOrEmpty($Username))
	{
		# Use compatibility mode for MSonline, AzureAD, SharePointOnline,
		if ($PSVersionTable.PSVersion.Major -igt 5)
		{
			Import-Module MSOnline -UseWindowsPowershell
			Import-Module AzureADPreview -UseWindowsPowershell
			Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowershell
			Import-Module Microsoft.Graph.Authentication -UseWindowsPowershell
			Import-Module Microsoft.Graph.Intune -UseWindowsPowershell -DisableNameChecking -ErrorAction SilentlyContinue
			Import-Module PnP.PowerShell -UseWindowsPowershell -DisableNameChecking -ErrorAction SilentlyContinue
		}
		#(Non) MFA, but Username is known!
		$commands = @('$Team = Connect-MicrosoftTeams -AccountId $Username', 'Connect-AzAccount -AccountId $Username | Out-Null',
			'Connect-MsolService -ErrorAction Stop', 'Connect-AzureAD -AccountId $Username -ErrorAction Stop | Out-Null',
			'Connect-ExchangeOnline -UserPrincipalName $Username -ShowBanner:$false',
			'Connect-SPOService -Url "https://$OrgName-admin.sharepoint.com" -Credential $Username -ErrorAction Stop',
			'Connect-MSGraph -AdminConsent -ErrorAction Stop | Out-Null', 'Connect-PnPOnline -ErrorAction Stop -Url "https://$OrgName.sharepoint.com" -Interactive',
			'$MSGraph = Connect-MgGraph -ErrorAction Stop -Scopes "AuditLog.Read.All","Policy.Read.All","Directory.Read.All","IdentityProvider.Read.All","Organization.Read.All","Securityevents.Read.All","ThreatIndicators.Read.All","SecurityActions.Read.All","User.Read.All","UserAuthenticationMethod.Read.All","MailboxSettings.Read"',
			'Connect-IPPSSession -ErrorAction Stop -UserPrincipalName $Username -WarningAction SilentlyContinue')
		
	}
	else
	{
		# Use compatibility mode for MSonline, AzureAD, SharePointOnline,
		if ($PSVersionTable.PSVersion.Major -igt 5)
		{
			Import-Module MSOnline -UseWindowsPowershell -WarningAction SilentlyContinue
			Import-Module AzureADPreview -UseWindowsPowershell -WarningAction SilentlyContinue
			Import-Module Microsoft.Online.SharePoint.PowerShell -UseWindowsPowershell -WarningAction SilentlyContinue
			Import-Module Microsoft.Graph.Authentication -UseWindowsPowershell -WarningAction SilentlyContinue
			Import-Module Microsoft.Graph.Intune -UseWindowsPowershell -DisableNameChecking -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
			Import-Module PnP.PowerShell -UseWindowsPowershell -DisableNameChecking -WarningAction SilentlyContinue
		}
		#MFA Authentication NO PASSWORD NO USERNAME
		$commands = @('$Team = Connect-MicrosoftTeams', 'Connect-AzAccount -ErrorAction Stop | Out-Null', 'Connect-MsolService -ErrorAction Stop',
			'Connect-AzureAD -ErrorAction Stop | Out-Null', 'Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop',
			'Connect-SPOService -ErrorAction Stop -Url "https://$OrgName-admin.sharepoint.com"', 'Connect-MSGraph -AdminConsent -ErrorAction Stop | Out-Null',
			'Connect-PnPOnline -WarningAction SilentlyContinue -ErrorAction Stop -Url "https://$OrgName.sharepoint.com" -Interactive',
			'$MSGraph = Connect-MgGraph -ErrorAction Stop -Scopes "AuditLog.Read.All","Policy.Read.All","Directory.Read.All","IdentityProvider.Read.All","Organization.Read.All","Securityevents.Read.All","ThreatIndicators.Read.All","SecurityActions.Read.All","User.Read.All","UserAuthenticationMethod.Read.All","MailboxSettings.Read"',
			'Connect-IPPSSession -WarningAction SilentlyContinue -ErrorAction Stop')
	}
	
<# Validation Scripts in order to determine if connection has been successful! #>
	$validation = @('-not [string]::IsNullOrEmpty($Team)', 'Get-AzAccessToken', '(Get-MsolUser -MaxResults 1) -ne $null',
		'(Get-AzureADUser -Top 1) -ne $null', '(Get-EXOMailbox -ResultSize 1) -ne $null',
		'(Get-SPOTenant) -ne $null', '(Get-IntuneManagedDevice -Top 1) -ne $null', '(Get-PnPAppAuthAccessToken) -ne $null',
		'$MSGraph -contains "Welcome To Microsoft Graph!"', '$Result = Get-RetentionCompliancePolicy; ($?) -eq $true')
	
<# Add the new name here#>
	$programs = @("Microsoft Teams", "Microsoft Azure PowerShell", "Microsoft Online Service", "Microsoft Azure Active Directory",
		"Microsoft Exchange Online", "Microsoft Sharepoint Online", "Microsoft InTune", "Microsoft PowerShell PnP", "Microsoft Graph",
		"Microsoft Exchange Security & Compliance Center")
	
	#To not do a for-loop, but to enable iteration inside a foreach loop that is parallel with the other functions
	$i = 0
	$j = 0
	
<# Actual Script #>	
	foreach ($command in $commands)
	{
		try { write-host "Connecting to $($programs[$i])..."; iex $command }
		catch
		{
			Write-Error "Could not Connect!"
			$i++
			$j++
			continue
		}
		if (iex $validation[$j])
		{
			Write-Host "Connected to: $($programs[$i])!" -ForegroundColor DarkYellow -BackgroundColor Black
			$i++
			$j++
		}
		else
		{
			Write-Error "Could not Validate!"
			$i++
			$j++
		}
	}
	
}