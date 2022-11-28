<#

  
  
 
.DESCRIPTION
    This script contains 1 function, Pre_Scan function:
    Prepares the windows enviroment for an authenticated scan by setting some registery values 
  
 
 
.NOTES   
    Name: Enable-RemoteRegistry
    Author: Provention Ltd
    Version: 1.2
    DateCreated: 15/11/2022
    DateUpdated: 15/11/2022

#>

echo "Setting remote registery to automatic, start service"

Set-Service -Name RemoteRegistry  -StartupType Automatic -ErrorAction Stop

Start-Service -InputObject (Get-Service -Name RemoteRegistry) -ErrorAction Stop


echo "-------------------------------------------------------------------------"

if(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -name LocalAccountToken)
{
   echo "Setting LocalAccountToken to 1 "
   Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -Name "LocalAccountToken" -Value "1" 

   Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountToken # -name "LocalAccountToken" -> to access a specific key
}

else
{
   echo "Creating LocalAccountToken"
   New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -Name "LocalAccountToken" -Value "1"  -PropertyType "DWORD"
   echo "Item has been set"
   Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountToken # -name "LocalAccountToken" -> to access a specific key
}


echo "-------------------------------------------------------------------------"



if( Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "forceguest" -Value "0"  -PropertyType "DWORD")
   echo "Creating HK "
   Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -Name "LocalAccountToken" -Value "1" 

   Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountToken -name "LocalAccountToken" -> to access a specific key
}

else
{
   echo "Setting forceguest"
   New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "forceguest" -Value "0"  -PropertyType "DWORD"
   echo "Item has been set"
   Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountToken # -name "LocalAccountToken" -> to access a specific key
}

echo "-------------------------------------------------------------------------"

if( Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "forceguest" -Value "0"  -PropertyType "DWORD")
   echo "Creating HK "
   Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -Name "LocalAccountToken" -Value "1" 

   Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountToken -name "LocalAccountToken" -> to access a specific key
}

else
{
   echo "Setting forceguest"
   New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "forceguest" -Value "0"  -PropertyType "DWORD"
   echo "Item has been set"
   Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountToken # -name "LocalAccountToken" -> to access a specific key
}
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$name`"" -Verb RunAs; exit } 
  netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes # Run as administrator







