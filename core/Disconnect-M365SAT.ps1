<# Disconnects modules after audit has been completed #>
function Disconnect-M365SAT
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
		try
		{
			Disconnect-AzAccount | Out-Null
		}
		catch
		{
			Clear-AzContext -Scope CurrentUser -Force
		}
	}
	catch
	{
		Write-Error "Microsoft Azure Powershell could not be Disconnected!"
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
		Write-Error "Microsoft Graph could not be Disconnected!"
	}
}