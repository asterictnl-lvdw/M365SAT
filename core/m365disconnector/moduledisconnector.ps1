<# Disconnects modules after audit has been completed #>
function Invoke-M365SATModuleDisconnection
{
<# Makes sure all modules are disconnected when the audit is done! #>
	Write-Output "Disconnecting from Microsoft Teams..."
	try
	{
		Disconnect-MicrosoftTeams
	}
	catch
	{
		Write-Error "Microsoft Teams could not be Disconnected!"
	}
	
	Write-Output "Disconnecting from Azure Powershell..."
	
	try
	{
		Disconnect-AzAccount | Out-Null
	}
	catch
	{
		Write-Error "Microsoft Azure Powershell could not be Disconnected!"
	}
	Write-Output "Disconnecting from Microsoft Online Service..."
	try
	{
		[Microsoft.Online.Administration.Automation.ConnectMsolService]::ClearUserSessionState()
	}
	catch
	{
		Write-Error "Microsoft Online Service could not be Disconnected!"
	}
	
	Write-Output "Disconnecting from Azure Active Directory..."
	try
	{
		Disconnect-AzureAD
	}
	catch
	{
		Write-Error "Microsoft Azure Active Directory could not be Disconnected!"
	}
	Write-Output "Disconnecting from Exchange Online & IPPSSession..."
	try
	{
		Disconnect-ExchangeOnline -Confirm:$false
	}
	catch
	{
		Write-Error "Microsoft Exchange Online & IPPSSession could not be Disconnected!"
	}
	
	Write-Output "Disconnecting from Microsoft SharePoint Online Service..."
	try
	{
		Disconnect-SPOService
	}
	catch
	{
		Write-Error "Microsoft Sharepoint Online Service could not be Disconnected!"
	}
	
	Write-Output "Disconnecting from Microsoft Intune & Microsoft Graph..."
	try
	{
		Disconnect-MgGraph | Out-Null
	}
	catch
	{
		Write-Error "Microsoft Teams could not be Disconnected!"
	}
	Write-Output "Disconnecting from Microsoft Powershell PnP..."
	try
	{
		Disconnect-PnPOnline
	}
	catch
	{
		Write-Error "Powershell PnP could not be Disconnected!"
	}
}