# v1.0.0beta 1-2-2023
The brand new release is now ready to be tested in beta. Warning: This is a BETA! Some parts of code might be unstable or not working properly. We are aware of issues and they will be eliminated in the stable version.

## What is New?
-	365Inspect+ has been changed to M365SAT
-	A brand new reporting engine that allows a much better overview of issues within your tenant. Besides that the report looks much more professional.
-	I have created the option to import M365SAT as a module or to run it the old way like 365Inspect+ did by executing a .ps1 script. In the future the release will also be installable through the PowerShell Gallery
-	Thanks to a change in the code less sensitive permissions are needed instead of Global Administrator. Global Reader and SharePoint Administrator will do the job now. SharePoint Administrator is still a sensitive permission, but because in the other roles of SharePoint it is not possible to read various values that are essential to audit SharePoint correctly.
-	We have removed the .json files for now and fused it with the .ps1 scripts. Now when the issue is found it will call a function that will return an PSCustomObject which is must faster than importing .json all the time. Leading to performance optimalization 
-	Some generic optimalization by changing some code within the engine
-	Added more console output where you can directly see if there are issues with inspectors finding things violating policy, etc.
-	The structure of modules is different. Now additional modules can be added to the script if needed. This makes the program even more modular 
-	Fixes output of the PowerShellScript where the remediation script was incorrectly displayed because of double quotes instead of single quotes
-	Added even more remediation powershell script possibilities to allow possibility to automate remediation of most scripts in the future
-	Categorized all modules within the report and by naming them e.g. {category}-{check}
-	CVSS 3.1 Scores are added within calculation. Based what could happen if the misconfiguration is abused
-	All modules have now an unique ID. In the future an list will be made with remediation so you can easily tell which issue has been found and how to remediate it. 
-	Fixed an issue where AzAccount is not disconnected properly leading to an exception within the PowerShell script. 
-	Optmized various inspectors’ code
-	Allowed easier authentication by providing username 

## Known Issues:
-	There is an issue with the ErrorLog not correctly capturing the message when an exception is thrown. The ErrorLog will be rewritten in the upcoming release
-	Some of the logs output are not being saved in the correct location. This will be fixed in the upcoming release
-	The online inspector download tool is not working yet, this is because the inspectors have not been published to the GitHub repository yet. 
-	The healthindex is not round and calculated correctly, thus looking a bit ugly, this will be fixed in the upcoming release.
-	There might be duplicates in some of the inspectors. This will be checked and fixed in the upcoming release
-	PowerShell 7 is partially compatible, but could result in a lot of bugs and code not working properly. It is still in the testing phase. If you encounter issues, please switch back to PowerShell 5.x and run the audit there. 
-	The updating mechanism to check for an update of M365SAT is not working properly yet, because it has not been published to GitHub yet. In future releases this will be briefly tested to check if this is working properly.
-	Some documentation might be added later


## To Implement:
- Get-NetRoute | ? DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where ConnectionState -eq 'Connected' (Which is for checking Network Connection)