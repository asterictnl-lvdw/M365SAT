# TO-DO List

## TO-DO (v2.3)

- The sorting of objects has now been properly fixed. As it sorts on score first and then on the ID **DONE**
- I have enhanced the PoShLog mechanism to ensure better error reporting when errors occur **DONE**
- The findings are now being moved to the corresponding folder and archived properly so no logs are all over the place **DONE**
- The permissions schema of Microsoft Graph will be changed in the next release. Someone else will scan which permissions are neccesary to implement **DONE**
- I have implemented a FIX for Microsoft PowerShell 5.1 as v3.x.x of Az.Accounts is not working with PowerShell 5.1. You will need to install v2.19.0 or earlier. For PowerShell 7 you can use the latest version as the mechanism is different **DONE**
- [#34](https://github.com/asterictnl-lvdw/M365SAT/issues/34) **DONE**
- [#38](https://github.com/asterictnl-lvdw/M365SAT/issues/38) **DONE**
- [#40](https://github.com/asterictnl-lvdw/M365SAT/issues/40) **DONE**

### Next Major Release (3.0)

- Fully cross-platform compatibility (including MacOSX and Linux) (v3.0)
- [#37](https://github.com/asterictnl-lvdw/M365SAT/issues/37) **NEXT-MAJOR-RELEASE**
- [#39](https://github.com/asterictnl-lvdw/M365SAT/issues/39) **NEXT-MAJOR-RELEASE**
- Creating a Docker-Container of M365SAT to run a containerized environment
- There is no detection for government issued environments and I do not know if the script does work for it (v3.0)
- Looking into the implementation with a service principal instead of a global admin account with respective permissions (v3.0)
- Implementing the CISA Benchmark and creating a mapping with the CIS benchmark (v3.0)
- Make a risk distribution Chart en make the other chart responsive instead of a static chart (v3.0)
- Add the posibility for 1-click remediation as you execute the PowerShell command via the browser by executing the command in the browser to look at this possibility (v3.0)
- We are going to start using PnP.Powershell alongside the Microsoft Sharepoint module to PnP PowerShell, due to wider compatibility and better support. (v3.0)
- Add additional objects within the finding-objects to enhance reporting mechanism (v3.0)
- Add the OK status so you will get a report including the things that are OK as well. (3-status-mechanism: OK,FAIL,UNKNOWN) (v3.0)

### Unknown

- We are going to widen the compatibility of MultiThreaded-Mode
- There are issues with MultiThreading when running Exchange Cmdlets. Source: https://learn.microsoft.com/en-us/powershell/exchange/invoke-command-workarounds-rest-api?view=exchange-ps we are looking into implementing the workaround to make this work so multithreading will be no issue with these cmdlets. Eventually these cmdlets will be executed in singlethreaded mode afterwards to make sure they succeed all.
- There are multiple issues with multithreading mode when executing the inspectors. This is being investigated, but there is no fix available at this moment. When this will be fixed is unknown