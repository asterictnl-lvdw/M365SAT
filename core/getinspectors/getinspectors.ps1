<# Downloads all Inspectors and creates list #>
function Get-M365SATGetInspectors
{
	<# This is only for the Online Version. And is in beta, this script will be improved upon future releases #>
<# Downloads the Inspectors from Github and extracts them to the powershellmodule location #>
	Invoke-WebRequest 'https://github.com/asterictnl-lvdw/M365SAT-inspectors/archive/refs/heads/main.zip' -OutFile $env:TEMP\inspectors.zip
	Expand-Archive $env:TEMP\inspectors.zip
	Rename-Item $env:TEMP\365inspect-main $env:TEMP\inspector
	dir -Path $env:TEMP\inspector -Recurse | Unblock-File #So no problems will occur when trying to execute inspectors
	$tempfiles += "$env:TEMP\inspectors.zip"
<# Creates List of All Inspectors #>
	$listinspectors = (Get-ChildItem -File $env:TEMP\inspector\*.ps1).Name | ForEach-Object { ($_ -split ".ps1")[0] }
	return $listinspectors #returning the whole list of inspectors *.ps1 files to ensure they could be used later
}

function Get-M365SATInspectorsOffline($Directory)
{
	<# This is the regular offline script that gets inspectors from offline #>
	dir -Path $Directory -Recurse | Unblock-File #So no problems will occur when trying to execute inspectors
	$listinspectors = (Get-ChildItem $Directory\*.ps1).Name | ForEach-Object { ($_ -split ".ps1")[0] }
	return $listinspectors
	
}