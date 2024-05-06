function Invoke-M365SATLogger($AllowLogging)
{
	if ($AllowLogging -eq "Verbose")
	{
		New-Logger |
		Set-MinimumLevel -Value Verbose |
		Add-SinkFile -Path "$OutPath\log\$($DateNow)_M365SAT.log" -OutputTemplate '{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception} {Properties:j}{NewLine}' |
		Add-SinkConsole |
		Start-Logger
	}
	elseif ($AllowLogging -eq "Debug")
	{
		New-Logger |
		Set-MinimumLevel -Value Debug |
		Add-SinkFile -Path "$OutPath\log\$($DateNow)_M365SAT.log" -OutputTemplate '{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception} {Properties:j}{NewLine}' |
		Add-SinkConsole - |
		Start-Logger
		Write-DebugLog "Program Started!"
	}
	elseif ($AllowLogging -eq "Info")
	{
		New-Logger |
		Set-MinimumLevel -Value Info |
		Add-SinkFile -Path "$OutPath\log\$($DateNow)_M365SAT.log" -OutputTemplate '{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception} {Properties:j}{NewLine}' |
		Add-SinkConsole |
		Start-Logger
		Write-InfoLog "Program Started!"
	}
	elseif ($AllowLogging -eq "Warning")
	{
		New-Logger |
		Set-MinimumLevel -Value Warning |
		Add-SinkFile -Path "$OutPath\log\$($DateNow)_M365SAT.log" -OutputTemplate '{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception} {Properties:j}{NewLine}' |
		Add-SinkConsole |
		Start-Logger
		Write-WarningLog "Program Started!"
	}
	elseif ($AllowLogging -eq "Error")
	{
		New-Logger |
		Set-MinimumLevel -Value Error |
		Add-SinkFile -Path "$OutPath\log\$($DateNow)_M365SAT.log" -OutputTemplate '{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception} {Properties:j}{NewLine}' |
		Add-SinkConsole |
		Start-Logger
		Write-ErrorLog "Program Started!"
	}
	elseif ($AllowLogging -eq "Fatal")
	{
		New-Logger |
		Set-MinimumLevel -Value Fatal |
		Add-SinkFile -Path "$OutPath\log\$($DateNow)_M365SAT.log" -OutputTemplate '{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception} {Properties:j}{NewLine}' |
		Add-SinkConsole |
		Start-Logger
		Write-FatalLog "Program Started!"
	}
	else
	{
		
	}
}
