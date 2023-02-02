# This is an MaliciousAttachmentTypesFilter Inspector.

# Date: 25-1-2023
# Version: 1.1
# Product Family: Microsoft Exchange
# Purpose: Checks if Malicious Attachment FileTypes are allowed
# Author: Leonardo van de Weteringh

# Enables error handling if you have the Write-ErrorLog script in the parent directory
$errorHandling = "$((Get-Item $PSScriptRoot).Parent.FullName)\Write-ErrorLog.ps1"

# Sets the Action Preference when an error occurs. Default is Stop
$ErrorActionPreference = "Stop"

# Calls the Error Handling to check if it is existing
. $errorHandling

# Define Output for file
$path = @($OutPath)

function Build-MaliciousAttachmentTypesFilter($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "M365SATFMEX0033"
		FindingName	     = "Dangerous Attachment Extensions are Not Filtered"
		ProductFamily    = "Microsoft Exchange"
		CVS			     = "9.6"
		Description	     = "Email is a primary vector of exploitation. It is common for attackers to send malicious file attachments designed to mimic legitimate business files. A list of historically malicious extensions that should be blocked/filtered from O365 emails is checked against the Tenant's malware filters to determine if these file types are being blocked. The file extensions listed herein are on this list of dangerous file extensions, but no O365 Malware Filter Policy is configured to filter them. Creating filters for these file types may decrease the risk of malware spreading within the organization through phishing or lateral phishing. The common malicious attachments defined in O365 at the time this document was authored are: xll, wll, rtf, reg, ws, wsf, vb, wsc, wsh, msh, msh1, msh2, mshxml, msh1xml, msh2xml, ps1, ps1xml, ps2, ps2xml, psc1, psc2, pif, msi, gadget, application, com, cpl, msc, hta, msp, bat, cmd, js, jse, scf, lnk, inf, dotm, xlsm, xltm, xlam, pptm, potm, ppam, ppsm, sldm"
		Remediation	     = "This finding refers to individual mailboxes that have Full Access delegated permissions. For these mailboxes, verify that the delegate access is expected, appropriate, and do not violate company policy."
		PowerShellScript = 'Set-MalwareFilterPolicy Default -FileTypes ade,adp,cpl,app,bas,asx,bat,chm,cmd,com,crt,csh,dotm,exe,fxp,hlp,hta,inf,ins,isp,js,jse,ksh,lnk,mda,mdb,mde,mdt,mdw,mdz,msc,msi,msp,mst,ops,pcd,pif,prf,prg,ps1,ps11,ps11xml,ps1xml,ps2,ps2xml,psc1,psc2,reg,scf,scr,sct,shb,shs,url,vb,vbe,vbs,wsc,wsf,wsh,xnk,ace,ani,docm,jar,asp,cer,der,dll,dos,gadget,Hta,Inf,Ins,Isp,Its,Jse,Ksh,Lnk,mad,maf,mag,mam,maq,mar,mas,mat,mau,mav,maw,msh,msh1,msh1xml,msh2,msh2xml,mshxml,obj,os2,plg,pst,rar,tmp,vsmacros,vsw,vxd,w16,ws,apk,appx,cab,iso,library,lib,msix,mhtml,msixbundle,terminal,plugin,font,command,bundle -EnableFileFilter $true'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings.ToString()
		Impact		     = "High"
		RiskRating	     = "High"
		References	     = @(@{ 'Name' = 'Turn on malware protection for your business'; 'URL' = "https://docs.microsoft.com/en-us/microsoft-365/business-video/anti-malware?view=o365-worldwide" },
			@{ 'Name' = '50+ File Extensions That Are Potentially Dangerous on Windows'; 'URL' = "https://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows" },
			@{ 'Name' = 'Set-MalwareFilterPolicy'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-malwarefilterpolicy?view=exchange-ps" })
	}
	return $inspectorobject
}


function Inspect-MaliciousAttachmentTypesFilter
{
	Try
	{
		
		# These file types are known to be used for malicious purposes.
		$executables = @("pif", "msi", "gadget", "application", "com", "cpl", "msc", "hta", "msp", "bat", "cmd", "js", "jse")
		$scripts = @("ws", "wsf", "vb", "wsc", "wsh", "msh", "msh1", "msh2", "mshxml", "msh1xml", "msh2xml", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2")
		$shortcuts = @("scf", "lnk", "inf")
		$macros = @("dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm")
		$othertypes = @("xll", "wll", "rtf", "reg")
		$mftypes = @()
		$mftypes += $executables + $scripts + $shortcuts + $marcros + $othertypes
		$uftypes = @()
		$malwarefilterpolicy = Get-MalwareFilterPolicy
		
		If ($malwarefilterpolicy.count -gt 0)
		{
			ForEach ($policy in $malwarefilterpolicy)
			{
				$FileTypes = $mftypes | Where { ($policy.FileTypes -notcontains $_) -and ($policy.EnableFileFilter -eq $true) }
				"Filter name: $($policy.Name) File Types not filtered: $($FileTypes -join "," | Select-Object -Unique); " | Out-File -FilePath "$($path)\MaliciousAttachmentsAllowed.txt" -Append
				$uftypes += $FileTypes
			}
			
		}
		else
		{
			return $null
		}
		
		if ($uftypes.count -gt 0)
		{
			$endobject = Build-MaliciousAttachmentTypesFilter($uftypes.count)
			return $endobject
		}
		return $null
		
	}
	Catch
	{
		Write-Warning "Error message: $_"
		$message = $_.ToString()
		$exception = $_.Exception
		$strace = $_.ScriptStackTrace
		$failingline = $_.InvocationInfo.Line
		$positionmsg = $_.InvocationInfo.PositionMessage
		$pscommandpath = $_.InvocationInfo.PSCommandPath
		$failinglinenumber = $_.InvocationInfo.ScriptLineNumber
		$scriptname = $_.InvocationInfo.ScriptName
		Write-Verbose "Write to log"
		Write-ErrorLog -message $message -exception $exception -scriptname $scriptname
		Write-Verbose "Errors written to log"
	}
	
}

return Inspect-MaliciousAttachmentTypesFilter


