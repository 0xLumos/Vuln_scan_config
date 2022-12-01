<#
  
  
 
.DESCRIPTION
    This script contains 2 function:
     enable function ->
      Prepares the windows enviroment for an authenticated scan by setting some registery values 
   
    disable function ->
      switch the windows enviroment to rest mode after an authenticated scan by clearing some registery values 
 
.NOTES   
    Name: Authenticated scan
    Author: Nour Alhouseini | Provention Ltd
    Version: 2.0
    DateCreated: 15/11/2022
    DateUpdated: 01/12/2022
     Github raw script : https://raw.githubusercontent.com/alhousen/Provention-/main/authenticated_scan.ps1
#>
function enable{
  echo "Setting remote registery to automatic, start service"

  Set-Service -Name RemoteRegistry  -StartupType Automatic -ErrorAction Stop

  Start-Service -InputObject (Get-Service -Name RemoteRegistry) -ErrorAction Stop

  echo "-------------------------------------------------------------------------"


  echo "Setting WMI to automatic, start service"

  #https://learn.microsoft.com/en-us/windows/win32/wmisdk/starting-and-stopping-the-wmi-service
  net start winmgmt
  echo "-------------------------------------------------------------------------"


#\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
# https://www.stigviewer.com/stig/windows_7/2017-02-21/finding/V-21950
 if(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ -name SmbServerNameHardeningLevel)
  {
     echo "Setting SmbServerNameHardeningLevel to 1 "
     Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ -Name "SmbServerNameHardeningLevel" -Value "1" 

     Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ | findstr SmbServerNameHardeningLevel # -name "LocalAccountToken" -> to access a specific key
  }

  else
  {
     echo "Creating SmbServerNameHardeningLevel"
     New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ -Name "SmbServerNameHardeningLevel" -Value "1"  -PropertyType "DWORD"
     echo "SmbServerNameHardeningLevel has been set"
     Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr SmbServerNameHardeningLevel # -name "LocalAccountToken" -> to access a specific key
  }



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
     echo "LocalAccountToken has been set"
     Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountToken # -name "LocalAccountToken" -> to access a specific key
  }


  echo "-------------------------------------------------------------------------"



  if( Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "forceguest" )
  {
     echo "Creating forceguest "
     Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -Name "forceguest" -Value "0" 

     Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr forceguest  #-> to access a specific key
  }

  else
  {
     echo "Setting forceguest"
     New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "forceguest" -Value "0"  -PropertyType "DWORD"
     echo "forceguest has been set"
     Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr forceguest # -name "LocalAccountToken" -> to access a specific key
  }

  echo "-------------------------------------------------------------------------"


  if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$name`"" -Verb RunAs; exit } 
    netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes # Run as administrator
    #rules enable = yes
  echo "Exiting..."
}




function disable{
  echo "Stopping remote registry service"

 

  Stop-Service -InputObject (Get-Service -Name RemoteRegistry) -ErrorAction Stop

  echo "-------------------------------------------------------------------------"

  
  echo "Stopping WMI service"



  #$s = Get-Service wmi
  #Stop-Service -InputObject $s -PassThru

  echo "-------------------------------------------------------------------------"

  Clear-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -name LocalAccountToken
  echo "LocalAccountToken deleted.."
 

  Clear-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -name forceguest
  echo "forceguest deleted.."


 
  


  if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$name`"" -Verb RunAs; exit } 
    netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=no # Run as administrator
    #rules enable = no
  echo "Exiting..."
}


$param1=$args[0]


if ($param1 -eq 'enable'){
    enable
}
elseif($param1 -eq 'disable') {
   disable
}
