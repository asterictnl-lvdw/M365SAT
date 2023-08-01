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

# Version 2.0

Finally it is here! After a long time of developing, bugfixing and testing I am finally able to release the v2.0 of Microsoft 365 Security Assessment Tool (M365SAT).

Many things have been changed, added, removed and fixed. I have made a comprehensive list for you to see what has changed:

## What is new:
- Updated the CIS benchmark to the latest v2.0.0 for both Microsoft Azure and Microsoft 365
- We have added parameters that can select which benchmark you want to check. In the future I will see if I can add another benchmark as well. Please do tell which benchmarks you are interested in so I can see what requirements are needed.
- Added brand new inspectors that enable new findings for both your Microsoft Azure and Microsoft 365 environment
- Removed some duplicate inspectors at multiple productfamilies
- Instead of 119 inspectors we now have 177 inspectors (this includes custom inspectors as well)
- We are testing a new login mechanism that allows better management when problems occur 
- We implemented a custom API caller which enables us to gain settings within the Azure tenant and other portals as well.
- We have added a M365SATTester.ps1 script that can be ran if you want to make use of M365SAT
- We have enabled autodetection for Sharepoint domains thanks to Soteria
- We have added a copy button onto the remediation script which allows easy copy of the remediation script where available.
- We have made the PowerShell scripts better readable thanks to Soteria and some additions
- We have changed the collapse menu's to a different style thanks to Bootstrap 5 with responsive chevrons for more professionalism
- We have added more Read permissions to Microsoft Graph to read further settings that are required for the CIS benchmark
- All Inspectors are working onto their latest version. And will be tested again once updates occur to see if there are any issues.
- M365SAT is partially compatible with PowerShell 7 now.
- We have enabled that you can execute M365SAT with lesser permissions now than Global Administrator.

## Fixed:
- We have fixed the HealthIndex in the report which is now cleanly a round number and gives now the correct health index. The problem was that the 100 was not deducted by the score resulting in a weaker score than it would be
- We have fixed issues with some priorities not displaying correctly as some informational noted inspectors were not sorted correctly
- We have fixed performance related issues with the Exchange cmdlets that have now less time needed to process thanks to the EXO cmdlets.
- We have fixed some logging issues where logs were not saved in the correct place resulting into errors if the directory was not created
- Fixed issues with the DMARC, DKIM and SPF records verification which is now done entirely by PowerShell commands instead of CMD commands
- Fixed resizing issues with the HTML report by removing multiple flex classes. Now if you make your screen smaller the objects will be smaller as well.
- We have fixed an issue that enabled correctly sorting the CVS 
- There was an issue with the start and end date in the report, this has been fixed so the correct start-date and end-date is written in the report now

## Changed:
- We have renamed multiple ps1 files to make their function more readable
- I have moved some things around in the report structure
- I have moved the inspector list to the end of the report to display all neccesary information first.
- Have updated all depedencies into the HTML report to their latest versions.
- I have migrated the Exchange commands to the new EXO cmdlet commands (V3) for better stability and performance.
- We have switched the authentication that Security & Compliance goes first and then Exchange due to a bug in the REST Schema that does not allow Exchange cmdlets to succeed when the Exchange cmdlet is being connected before the S&C Cmdlet
O I have migrated Bootstrap 4 to Bootstrap 5 which enhances the prettiness of the report
O I have updated the JQuery and FontAwesome dependencies to their latest version without any issues. 

## Removed:
- We have said goodbye to the PnPPowerShell modules for now as we want to take full potential of the Sharepoint Cmdlet
- We have said goodbye to the AzureADPreview and MicrosoftOnline (MSOL) modules as they will be phased out by Microsoft and replaced by Microsoft Graph
- We have said goodbye to the Microsoft InTune module which is now fully implemented in Microsoft Graph itself
- We have removed the Write-ErrorLog.ps1 and replaced it with PoSHLog which allows us better logging as it looks more clean. 

## Known Issues and Bugs:
- Logfiles are not pointed to the correct folder. This will be fixed in the upcoming release. You can manually open the corresponding txt file as a workaround for now. This has to do with the directory created in a later phase as we will create the directory earlier in the upcoming release
- The CVS might have incorrect scores. I will change the scores based on CWE findings and based onto a custom priority algorithm to determine what has big priority for general users and what has not.
- Some modules require manual authentication due to their cmdlet does not support cached credentials authentication.
- On PowerShell 5.1 CISAz6000 gives an warning about 'Microsoft.Azure.PowerShell.Cmdlets.Network'. This can be safely ignored. In the next release I will check if I can supress the issue
- Not all Text files have the correct naming yet. This will be fixed in the next upcoming release.
- There might be duplicate logs of some findings. This is due some objects have more than 10 stored into the array. We will be fixing the issue so objects are automatically pointed to output in the next release
- The Clipboard function does not work with all internet browsers. If you are encountering issues, please open the html file in a different browser e.g. Microsoft Edge
- In PowerShell 7 the following inspectors do not work: CISMEx230, CISMEx280, CSTM-Ex013, CSTM-Ex014, CSTM-Ex015, CSTM-Ex016, CSTM-Ex023, CSTM-Ex024, CSTM-Ex025, CSTM-Ex026 and CSTM-Ex027. This has to do with some issues within the new EXO commands that are not entirely working properly with PowerShell 7 yet. Only Exchange is impacted for now. We are looking to revert back from EXO to the normal commands in some test-releases to see if that resolves the issue for now and archive the EXO inspectors for later use.


# TO-DO IN UPCOMING VERSIONS
- Change CVS to CWE with a custom score based by Aster calculated with the CVSS V4.0
- A brand new remediation schema with brand new priorities based on professional advice. 
- Add the new scripts that enable remediation via Microsoft Graph and the other endpoints
- Add the posibility for 1-click remediation as you execute the PowerShell command via the browser
- Take the Exception part into a core module to eliminate the stuff out of the Powershell script
- Migrate all the Information parts to a different powershell script
- Impact will be removed / redefined based on the remediation and not on the risk
- Risk will be based on the CWE and calculated by Aster in combination with the CVSS and a (generic) Risk-Analysis method
- RemediationScript will be added in the object
- Directory will be created earlier to get the new path name so the logfiles will be stored in the correct folder and pointed to the correct folder
- We are seperating some functions as they are serving as a core module in the future which will be a seperate .ps1 file for better managability
- Powershell 7 Compatibility
- Make a risk distribution Chart en make the other chart responsive instead of a static chart
- Every check will be required to give some output (if something is found of course!) and save this to the findings folder within the reports folder
- We are looking to implement NIST or another framework as well in the future
- Testing a network connection script that allows only this scrip to be run when user is actually online. Get-NetRoute | ? DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where ConnectionState -eq 'Connected' (Which is for checking Network Connection)
- Fully cross-platform compatibility by removing as many platform dependencies and replacing them by initiating them via API connections.