<#
.Synopsis
    This will enable the remote registry service on local or remote computers.
  
  
 
.DESCRIPTION
    This will enable the remote registry service on local or remote computers.
  
 
 
.NOTES   
    Name: Enable-RemoteRegistry
    Author: Provention Ltd
    Version: 1.0
    DateCreated: 15/11/2022
    DateUpdated: 15/11/2022
 
 
#>

function Pre_Scan {
#Display all keys and values in this registery 
	Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\

	Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ # -name "LocalAccountToken" -> to access a specific key
#STEP1: Local account token sat to 0
	New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -Name "LocalAccountToken" -Value ”1"  -PropertyType "DWORD"
#STEP2: forceguest registery sat to 1 
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "forceguest" -Value ”0"  -PropertyType "DWORD"
#STEP3: Local service sat to READ
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg -Name "Local Service" -Value ”READ"  -PropertyType "String"
#STEP4: Administrators have full control 
	New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg -Name "Administrators" -Value ”FULL CONTROL"  -PropertyType "String"
#STEP5: Change remote registery and WMI service startup type to Automatic and start that service
  Set-Service -Name RemoteRegistry  -StartupType Automatic -ErrorAction Stop
  Start-Service -InputObject (Get-Service -Name RemoteRegistry) -ErrorAction Stop
  #Set-Service -Name RemoteRegistry  -StartupType Automatic -ErrorAction Stop
  #Start-Service -InputObject (Get-Service -Name RemoteRegistry) -ErrorAction Stop
#STEP6: ALLOW ACCESS TO WMI THROUGH DEFENDER
	if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$name`"" -Verb RunAs; exit } 
	netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes # Run as administrator
}
Pre_Scan
