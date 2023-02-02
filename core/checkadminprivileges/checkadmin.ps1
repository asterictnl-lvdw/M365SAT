function CheckAdminPrivBeta
{
	# Check if script is running as Adminstrator and if not use RunAs
	Write-Host "[...] Checking if the script is running as Administrator"
	$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
	if (-not $IsAdmin)
	{	
			Write-Warning "[!] Program needs Administrator Rights! You cannot run this in normal user mode!"
			break
	}
	else
	{
		Write-Host "[+] The script is running as Administrator..." -ForegroundColor Green
	}
}
