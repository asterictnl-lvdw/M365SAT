# Date: 25-1-2023
# Version: 1.0
# Benchmark: Custom
# Product Family: Microsoft Exchange
# Purpose: Checks if Attachment Extensions which are dangerous are filtered
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

#Call the OutPath Variable here
$path = @($OutPath)

function Build-CSTM-Ex018($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CSTM-Ex018"
		FindingName	     = "CSTM-Ex018 - Dangerous Attachment Extensions are Not Filtered"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "12"
		Description	     = "Email is a primary vector of exploitation. It is common for attackers to send malicious file attachments designed to mimic legitimate business files. A list of historically malicious extensions that should be blocked/filtered from O365 emails is checked against the Tenant's malware filters to determine if these file types are being blocked. The file extensions listed herein are on this list of dangerous file extensions, but no O365 Malware Filter Policy is configured to filter them. Creating filters for these file types may decrease the risk of malware spreading within the organization through phishing or lateral phishing. The common malicious attachments defined in O365 at the time this document was authored are: xll, wll, rtf, reg, ws, wsf, vb, wsc, wsh, msh, msh1, msh2, mshxml, msh1xml, msh2xml, ps1, ps1xml, ps2, ps2xml, psc1, psc2, pif, msi, gadget, application, com, cpl, msc, hta, msp, bat, cmd, js, jse, scf, lnk, inf, dotm, xlsm, xltm, xlam, pptm, potm, ppam, ppsm, sldm"
		Remediation	     = "This finding refers to individual mailboxes that have Full Access delegated permissions. For these mailboxes, verify that the delegate access is expected, appropriate, and do not violate company policy."
		PowerShellScript = 'Set-MalwareFilterPolicy Default -FileTypes ade,adp,cpl,app,bas,asx,bat,chm,cmd,com,crt,csh,dotm,exe,fxp,hlp,hta,inf,ins,isp,js,jse,ksh,lnk,mda,mdb,mde,mdt,mdw,mdz,msc,msi,msp,mst,ops,pcd,pif,prf,prg,ps1,ps11,ps11xml,ps1xml,ps2,ps2xml,psc1,psc2,reg,scf,scr,sct,shb,shs,url,vb,vbe,vbs,wsc,wsf,wsh,xnk,ace,ani,docm,jar,asp,cer,der,dll,dos,gadget,Hta,Inf,Ins,Isp,Its,Jse,Ksh,Lnk,mad,maf,mag,mam,maq,mar,mas,mat,mau,mav,maw,msh,msh1,msh1xml,msh2,msh2xml,mshxml,obj,os2,plg,pst,rar,tmp,vsmacros,vsw,vxd,w16,ws,apk,appx,cab,iso,library,lib,msix,mhtml,msixbundle,terminal,plugin,font,command,bundle -EnableFileFilter $true'
		DefaultValue	 = "0"
		ExpectedValue    = "0"
		ReturnedValue    = $findings
		Impact		     = "3"
		Likelihood	     = "4"
		RiskRating	     = "High"
		Priority		 = "High"
		References	     = @(@{ 'Name' = '50+ File Extensions That Are Potentially Dangerous on Windows'; 'URL' = "https://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows" },
			@{ 'Name' = 'Set-MalwareFilterPolicy'; 'URL' = "https://docs.microsoft.com/en-us/powershell/module/exchange/set-malwarefilterpolicy?view=exchange-ps" })
	}
	return $inspectorobject
}


function Inspect-CSTM-Ex018
{
	Try
	{
		# This is a full list
		$fulllist = @("ade", " adp", " cpl", " app", " bas", " asx", " bat", "chm", "cmd", " com", "crt", "csh", "dotm", "exe", "fxp", "hlp", "hta", "inf", "ins", "isp", "js", "jse", "ksh", "lnk", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "msc", "msi", "msp", "mst", "ops", "pcd", "pif", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "reg", "scf", "scr", "sct", "shb", "shs", "url", "vb", "vbe", "vbs", "wsc", "wsf", "wsh", "xnk", "ace", "ani", "docm", "jar", "asp", "cer", "der", " dll", "dos", "gadget", "Hta", "Inf", "Ins", "Isp", "Its", "Jse", "Ksh", "Lnk", "mad", "maf", "mag", "mam", "maq", "mar", "mas", "mat", "mau", "mav", "maw", "msh", "msh1", "msh1xml", "msh2", "msh2xml", "mshxml", "obj", "os2", "plg", "pst", "rar", "tmp", "vsmacros", "vsw", "vxd", "w16", "ws", "apk", "appx", "cab", "iso", "library", "lib", "msix", "mhtml", "msixbundle", "terminal", "plugin", "font", "command", "bundle")
		# These file types are known to be used for malicious purposes. These are categorized 
		$executables = @("pif", "msi", "gadget", "application", "com", "cpl", "msc", "hta", "msp", "bat", "cmd", "js", "jse", "exe")
		$scripts = @("ws", "wsf", "vb", "wsc", "wsh", "msh", "msh1", "msh2", "mshxml", "msh1xml", "msh2xml", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "bat", "vbs")
		$shortcuts = @("scf", "lnk", "inf")
		$macros = @("dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm")
		$othertypes = @("xll", "wll", "rtf", "reg", "dll")
		$mftypes = @()
		$mftypes += $executables + $scripts + $shortcuts + $marcros + $othertypes
		$uftypes = @()
		$ufttypescount = 0
		$malwarefilterpolicy = Get-MalwareFilterPolicy
		
		If ($malwarefilterpolicy.count -gt 0)
		{
			ForEach ($policy in $malwarefilterpolicy)
			{
				foreach ($type in $fulllist)
				{
					if (!($policy.FileTypes).contains($type))
					{
						#Raise the count
						$ufttypescount++
						#Add the type to the list
						$uftypes += $type
					}
				}
				#Save the list to a txt file
				"Filter name: $($policy.Name) File Types not filtered: $($uftypes -join "," | Select-Object -Unique); " | Out-File -FilePath "$($path)\MaliciousAttachmentsAllowed.txt" -Append
				# Reset the array because it else prints out twice
				$uftypes = @()
			}
		}
		else
		{
			return $null
		}
		
		if ($ufttypescount -igt 0)
		{
			$endobject = Build-CSTM-Ex018($ufttypescount)
			return $endobject
		}
		return $null
		
	}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CSTM-Ex018


