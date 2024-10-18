# Date: 25-1-2023
# Version: 1.0
# Benchmark: CIS Microsoft 365 v3.1.0
# Product Family: Microsoft Exchange
# Purpose: Checks common malicious attachments and if they are filtered properly
# Author: Leonardo van de Weteringh

# New Error Handler Will be Called here
Import-Module PoShLog

# Determine OutPath
$path = @($OutPath)

function Build-CISMEx2114($findings)
{
	#Actual Inspector Object that will be returned. All object values are required to be filled in.
	$inspectorobject = New-Object PSObject -Property @{
		ID			     = "CISMEx2114"
		FindingName	     = "CIS MEx 2.1.14 - No comprehensive attachment filtering is applied!"
		ProductFamily    = "Microsoft Exchange"
		RiskScore	     = "10"
		Description	     = "Blocking known malicious file types can help prevent malware-infested files from infecting a host or performing other malicious attacks such as phishing and data extraction. Defining a comprehensive list of attachments can help protect against additional unknown and known threats. Many legacy file formats, binary files and compressed files have been used as delivery mechanisms for malicious software. Organizations can protect themselves from Business E-mail Compromise (BEC) by allow-listing only the file types relevant to their line of business and blocking all others"
		Remediation	     = "Run the following Exchange Online PowerShell command"
		PowerShellScript = 'New-MalwareFilterPolicy @Policy -FileTypes $L2Extensions; New-MalwareFilterRule @Rule'
		DefaultValue	 = "28 unique filetypes"
		ExpectedValue    = "120 unique filetypes"
		ReturnedValue    = $findings
		Impact		     = "2"
		Likelihood	     = "5"
		RiskRating	     = "Medium"
		Priority		 = "Medium"
		References	     = @(@{ 'Name' = 'Configure anti-malware policies in EOP'; 'URL' = 'https://learn.microsoft.com/en-us/defender-office-365/anti-malware-policies-configure?view=o365-worldwide' })
	}
}


function Inspect-CISMEx2114
{
	Try
	{
		# This is the list with filetypes that should be filtered based on the CIS benchmark
		$L2Extensions = @(
		"7z", "a3x", "ace", "ade", "adp", "ani", "app", "appinstaller",
		"applescript", "application", "appref-ms", "appx", "appxbundle", "arj",
		"asd", "asx", "bas", "bat", "bgi", "bz2", "cab", "chm", "cmd", "com",
		"cpl", "crt", "cs", "csh", "daa", "dbf", "dcr", "deb",
		"desktopthemepackfile", "dex", "diagcab", "dif", "dir", "dll", "dmg",
		"doc", "docm", "dot", "dotm", "elf", "eml", "exe", "fxp", "gadget", "gz",
		"hlp", "hta", "htc", "htm", "htm", "html", "html", "hwpx", "ics", "img",
		"inf", "ins", "iqy", "iso", "isp", "jar", "jnlp", "js", "jse", "kext",
		"ksh", "lha", "lib", "library-ms", "lnk", "lzh", "macho", "mam", "mda",
		"mdb", "mde", "mdt", "mdw", "mdz", "mht", "mhtml", "mof", "msc", "msi",
		"msix", "msp", "msrcincident", "mst", "ocx", "odt", "ops", "oxps", "pcd",
		"pif", "plg", "pot", "potm", "ppa", "ppam", "ppkg", "pps", "ppsm", "ppt",
		"pptm", "prf", "prg", "ps1", "ps11", "ps11xml", "ps1xml", "ps2", 
		"ps2xml", "psc1", "psc2", "pub", "py", "pyc", "pyo", "pyw", "pyz", 
		"pyzw", "rar", "reg", "rev", "rtf", "scf", "scpt", "scr", "sct",
		"searchConnector-ms", "service", "settingcontent-ms", "sh", "shb", "shs",
		"shtm", "shtml", "sldm", "slk", "so", "spl", "stm", "svg", "swf", "sys",
		"tar", "theme", "themepack", "timer", "uif", "url", "uue", "vb", "vbe",
		"vbs", "vhd", "vhdx", "vxd", "wbk", "website", "wim", "wiz", "ws", "wsc",
		"wsf", "wsh", "xla", "xlam", "xlc", "xll", "xlm", "xls", "xlsb", "xlsm",
		"xlt", "xltm", "xlw", "xml", "xnk", "xps", "xsl", "xz", "z"
		)

		# Initialize counters
		$Violation = @()
		$ExtensionReport = @()
		$MissingCount = 0

		#MalwarePolicy
		$MalwarePolicies = Get-MalwareFilterPolicy
		foreach ($MalwarePolicy in $MalwarePolicies){
			if ($MalwarePolicy.EnableFileFilter -eq $false) {
				Write-Warning "$($MalwarePolicy.Identity): Common Attachments Filter is disabled"
				$Violation += "$($MalwarePolicy.Identity): Common Attachments Filter is disabled"
			}
		}
		#FilterRules
		$FilterRules = Get-MalwareFilterRule
		foreach ($FilterRule in $FilterRules){
			if ($FoundRule.State -eq 'Disabled' -or $null) {
				Write-Warning "WARNING: The Anti-malware rule is disabled."
				$Violation += "Anti-Malware Rule is disabled"
			}
		}
		#ExtensionPolicy
		$ExtensionPolicies = Get-MalwareFilterPolicy | Where-Object {$_.FileTypes.Count -ilt 120}
		foreach($ExtensionPolicy in $ExtensionPolicies){
			if ($ExtensionPolicies.FileTypes.Count -eq 0){
				Write-Warning "$($ExtensionPolicy.Identity) does not have any filetypes filtered!"
				$Violation += "Amount of Extensions in $($ExtensionPolicy.Identity): $(($MalwarePolicy.FileTypes).Count)"
				$MissingExtensions = $L2Extensions | Where-Object { $extension = $_; -not $ExtensionPolicy.FileTypes.Contains($extension) }
				if ($MissingExtensions.Count -igt 0){
					$MissingCount++
					 $ExtensionReport += @{
					 Identity = $policy.Identity 
					MissingExtensions = $MissingExtensions -join ', '
					}
				}
			}else{
				Write-Warning "$($ExtensionPolicy.Identity) does contain only $(($ExtensionPolicies.FileTypes).Count) extensions!"
				$Violation += "Amount of Extensions in $($ExtensionPolicy.Identity): $(($MalwarePolicy.FileTypes).Count)"
				$MissingExtensions = $L2Extensions | Where-Object { $extension = $_; -not $ExtensionPolicy.FileTypes.Contains($extension) }
				if ($MissingExtensions.Count -igt 0){
					$MissingCount++
					 $ExtensionReport += @{
					 Identity = $ExtensionPolicy.Identity 
					 MissingExtensions = $MissingExtensions -join ', '
					}
				}
			}
		}

		#Wrapup report
		if ($MissingCount -igt 0) {
			foreach ($fpolicy in $ExtensionReport) {
				$MissingExtensions = $fpolicy.MissingExtensions.Split(",")
				$Violation += "$($fpolicy.Identity) is missing the following extension filters: $($fpolicy.MissingExtensions) \n"
			}
		}

		#Final check
		if ($Violation.Count -igt 0)
		{
			$Violation | Format-Table -AutoSize | Out-File "$path\CISMEx2114-MalwareFilterRule.txt"
			$finalobject = Build-CISMEx2114("file://$path\CISMEx2114-MalwareFilterRule.txt")
			return $finalobject
		}
		return $null
		
		}
	catch
	{
		Write-WarningLog 'The Inspector: {inspector} was terminated!' -PropertyValues $_.InvocationInfo.ScriptName
		Write-ErrorLog 'An error occured on line {line} char {char} : {error}' -ErrorRecord $_ -PropertyValues $_.InvocationInfo.ScriptLineNumber, $_.InvocationInfo.OffsetInLine, $_.InvocationInfo.Line
	}
	
}

return Inspect-CISMEx2114


