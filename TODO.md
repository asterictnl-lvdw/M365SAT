# TO-DO List

### TO-DO (v3.0)
- Object-Sorting Fix, due to a bug where the sorting was not correctly done resulting into a messed up report [#47](https://github.com/asterictnl-lvdw/M365SAT/issues/47)
- Multiple Conditional Access Enhancements where possible to improve accuracy with auditing
- Fully cross-platform compatibility (including MacOSX and Linux) **IN-PROGRESS**
- [#37](https://github.com/asterictnl-lvdw/M365SAT/issues/37)
- [#39](https://github.com/asterictnl-lvdw/M365SAT/issues/39) **DONE**
- Creating a Docker-Container of M365SAT to run a containerized environment.
- Add XML and JSON support as output possibility **IN-PROGRESS**
- There is no detection for government issued environments and I do not know if the script does work for it. **DONE**
- Looking into the implementation with a service principal instead of a global admin account with respective permissions.
- Implementing the CISA Benchmark and creating a mapping with the CIS benchmark. **IN-PROGRESS**
- Make a risk distribution Chart en make the other chart responsive instead of a static chart.
- Add the posibility for 1-click remediation as you execute the PowerShell command via the browser by executing the command in the browser to look at this possibility.
- We are going to start using PnP.Powershell alongside the Microsoft Sharepoint module to PnP PowerShell, due to wider compatibility and better support.
- Add additional objects within the finding-objects to enhance reporting mechanism.
- Add the OK status so you will get a report including the things that are OK as well. (3-status-mechanism: OK,FAIL,UNKNOWN).
- Replaced the AzAccount MultiAPI Connector with a no dependency connector, the only thing is that you need to authenticate once to gather the token to authenticate to the endpoints. **DONE**

### Unknown

- We are going to widen the compatibility of MultiThreaded-Mode.
- There are issues with MultiThreading when running Exchange Cmdlets. Source: https://learn.microsoft.com/en-us/powershell/exchange/invoke-command-workarounds-rest-api?view=exchange-ps we are looking into implementing the workaround to make this work so multithreading will be no issue with these cmdlets. Eventually these cmdlets will be executed in singlethreaded mode afterwards to make sure they succeed all.
- There are multiple issues with multithreading mode when executing the inspectors. This is being investigated, but there is no fix available at this moment. When this will be fixed is unknown.