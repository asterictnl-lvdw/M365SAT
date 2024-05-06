<# Checks if M365SAT is up-to-date! #>
<# This function is under construction and may not work yet. For now it will catch the exception and proceed to the next task! #>
function Check-M365SATUpdates
{
	param
	(
		$Terminate,
		[Boolean]$GalleryCheck
	)
	
<# Checks for Updates regarding M365SAT or the Preview Version #>
	
	
	

	Write-Host "$(Get-Date) Performing M365SAT Version check..."
	$Updated = $False
	# When detected we are running the preview release
	$Preview = $False
	try
	{
		try
		{
			$InspectVersion = (Get-Module M365SAT | Sort-Object Version -Desc)[0].Version
		}
		catch
		{
			$InspectVersion = (Get-Module M365SATPreview | Sort-Object Version -Desc)[0].Version
			if ($InspectVersion) { $Preview = $true }
		}
		
		if ($GalleryCheck)
		{
			if ($Preview -eq $False)
			{
				$PSGalleryVersion = (Find-Module M365SAT -Repository PSGallery -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue).Version
			}
			else
			{
				$PSGalleryVersion = (Find-Module M365SATPreview -Repository PSGallery -ErrorAction:SilentlyContinue -WarningAction:SilentlyContinue).Version
			}
			if ($PSGalleryVersion -gt $InspectVersion)
			{
				$Updated = $False
				
				#Execute the Update365InspectPlus script from Github to download the new 
				iex (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/karmakstylez/365inspectplus/master/UpdateM365SAT.ps1") #Download & Execute Update Script
				stop-process -Id $PID #Stops current script to make sure update will not error
			}
			else
			{
				Write-Warning "$($Module) is up-to-date!"
			}
		}
	}
	catch
	{
		Write-Error "Error Checking Updates..."
	}
}