<# Disconnects modules after audit has been completed #>
function Disconnect-M365SAT($Modules)
{
	$DisconnectAzure = $false
	$DisconnectGraph = $false
	$DisconnectExchange = $false
	$DisconnectSharepoint = $false
	$DisconnectTeams = $false

	switch ($Modules) {
		"Azure" {
			Write-Output "Disconnecting from Microsoft Azure..."

				try
				{
					Disconnect-AzAccount | Out-Null
					$DisconnectAzure = $True
				}
				catch
				{
					Write-Error "Microsoft Azure could not be Disconnected!"
					Clear-AzContext -Scope CurrentUser -Force
				}
			Write-Output "Disconnecting Microsoft Graph..."
			try
			{
				Disconnect-MgGraph | Out-Null
				$DisconnectGraph = $True
			}
			catch
			{
				Write-Error "Microsoft Graph could not be Disconnected!"
			}
		  }
		"Exchange" {
			Write-Output "Disconnecting Microsoft Exchange & Security Compliance Center..."
			try
			{
				Disconnect-ExchangeOnline -Confirm:$false
				$DisconnectExchange = $true
			}
			catch
			{
				Write-Error "Microsoft Exchange & Security Compliance Center could not be Disconnected!"
			}
		}
		"Office365"{
			if ($DisconnectAzure -ne $true){
				Write-Output "Disconnecting from Microsoft Azure..."

				try
				{
					Disconnect-AzAccount | Out-Null
					$DisconnectAzure = $True
				}
				catch
				{
					Write-Error "Microsoft Azure could not be Disconnected!"
					Clear-AzContext -Scope CurrentUser -Force
				}
			}
			if ($DisconnectGraph -ne $true){
				Write-Output "Disconnecting Microsoft Graph..."
				try
				{
					Disconnect-MgGraph | Out-Null
					$DisconnectGraph = $True
				}
				catch
				{
					Write-Error "Microsoft Graph could not be Disconnected!"
				}
			}
		}
		"Sharepoint"{
			if ($DisconnectGraph -ne $True){
				Write-Output "Disconnecting Microsoft Graph..."
			try
			{
				Disconnect-MgGraph | Out-Null
				$DisconnectGraph = $true
			}
			catch
			{
				Write-Error "Microsoft Graph could not be Disconnected!"
			}
			}
			Write-Output "Disconnecting Microsoft SharePoint..."
			try
			{
				Disconnect-SPOService
				$DisconnectSharepoint = $true
			}
			catch
			{
				Write-Error "Microsoft Sharepoint could not be Disconnected!"
			}
		}
		"Teams"{
			if ($DisconnectGraph -ne $True){
				Write-Output "Disconnecting Microsoft Graph..."
			try
			{
				Disconnect-MgGraph | Out-Null
				$DisconnectGraph = $true
			}
			catch
			{
				Write-Error "Microsoft Graph could not be Disconnected!"
			}
			}
			Write-Output "Disconnecting Microsoft Teams..."
			try
			{
				Disconnect-MicrosoftTeams
				$DisconnectTeams = $true
			}
			catch
			{
				Write-Error "Microsoft Teams could not be Disconnected!"
			}
		}
	}
<# Makes sure all modules are disconnected when the audit is done! #>
	
	



	

	

}