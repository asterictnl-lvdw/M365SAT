function Invoke-M365SATLogger
{
	param(
		[string]$RootDirectory
	)
	
	if ($RootDirectory.Contains('\')){
		# Dirty-way of checking Windows
		Start-Logger -FilePath "$RootDirectory\log\$($DateNow)_M365SAT.log" -Console -MinimumLevel Warning
		Write-WarningLog "Program Started!"
	}
	elseif ($RootDirectory.Contains('/')) {
		# Dirty-way of checking Linux
		Start-Logger -FilePath "$RootDirectory/log/$($DateNow)_M365SAT.log" -Console -MinimumLevel Warning
		Write-WarningLog "Program Started!"
	}
}
