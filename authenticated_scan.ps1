<#
  
  
 
.DESCRIPTION
    This script contains 2 function:
     enable function ->
      Prepares the windows enviroment for an authenticated scan by setting some registery values 
   
    disable function ->
      switch the windows enviroment to rest mode after an authenticated 
 
.NOTES   
    Name: Authenticated scan
    Author: Nour Alhouseini | Provention Ltd
    Version: 3.2
    DateCreated: 15/11/2022
    DateUpdated: 06/01/2023
    Github raw script : https://raw.githubusercontent.com/alhousen/Provention-/main/authenticated_scan.ps1
#>
function enable{
  echo "Setting remote registery to automatic, start service"

  Set-Service -Name RemoteRegistry  -StartupType Automatic -ErrorAction Stop

  Start-Service -InputObject (Get-Service -Name RemoteRegistry) -ErrorAction Stop

  echo "-------------------------------------------------------------------------"




  #Prohibit use of Internet Connection Sharing on your DNS domain network
  #https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.NetworkConnections::NC_ShowSharedAccessUI
#   if(Get-ItemProperty 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' -name NC_PersonalFirewallConfig)
#   {
#      echo "Setting NC_ShowSharedAccessUI to 1 (Disable) "
#      Set-ItemProperty -Path 'HKLM:SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Services\FileAndPrint' -Name "NC_ShowSharedAccessUI" -Value "1" 

#      Get-ItemProperty 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' | findstr NC_ShowSharedAccessUI # -name "NC_PersonalFirewallConfig" -> to access a specific key
#   }

#   else
#   {
#      echo "Creating NC_ShowSharedAccessUI"
#      New-ItemProperty -Path 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' -Name "NC_ShowSharedAccessUI" -Value "1"  -PropertyType "DWORD"
#      echo "NC_ShowSharedAccessUI has been set"
#      Get-ItemProperty 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' | findstr NC_ShowSharedAccessUI # -name "NC_ShowSharedAccessUI" -> to access a specific key
#   }





  #Prohibit use of Internet Connection Firewall on your DNS domain network
  #https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.NetworkConnections::NC_PersonalFirewallConfig
  if(Get-ItemProperty 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' -name NC_PersonalFirewallConfig)
  {
     echo "Setting NC_PersonalFirewallConfig to 1 (Disable) "
     Set-ItemProperty -Path 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' -Name "NC_PersonalFirewallConfig" -Value "1" 

     Get-ItemProperty 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' | findstr NC_PersonalFirewallConfig # -name "NC_PersonalFirewallConfig" -> to access a specific key
  }

  else
  {
     echo "Creating NC_PersonalFirewallConfig"
     New-ItemProperty -Path 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' -Name "NC_PersonalFirewallConfig" -Value "1"  -PropertyType "DWORD"
     echo "NC_PersonalFirewallConfig has been set"
     Get-ItemProperty 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' | findstr NC_PersonalFirewallConfig # -name "NC_PersonalFirewallConfig" -> to access a specific key
  }


  #SPN TARGET VALIDATION
  #\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
  #https://www.vjonathan.com/post/windows-10-1709-and-smbservernamehardeninglevel/
   if(Get-ItemProperty  HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ -name RequiredPrivileges)
    {
       echo "Setting RequiredPrivileges to SeTcbPrivilege "
       echo "Documentation: https://www.vjonathan.com/post/windows-10-1709-and-smbservernamehardeninglevel/ "
       Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ -Name "RequiredPrivileges" -Value "SeTcbPrivilege" 

       Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ | findstr RequiredPrivileges # -name "RequiredPrivileges" -> to access a specific key
    }

    else
    {
       echo "Creating RequiredPrivileges"
       New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ -Name "RequiredPrivileges" -Value "SeTcbPrivilege"  -PropertyType "String"
       echo "RequiredPrivileges has been set"
       Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ | findstr RequiredPrivileges # -name "RequiredPrivileges" -> to access a specific key
    }



  if(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -name LocalAccountTokenFilterPolicy)
  {
     echo "Setting LocalAccountTokenFilterPolicy to 1 "
     Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -Name "LocalAccountTokenFilterPolicy" -Value "1" 

     Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountTokenFilterPolicy # -name "LocalAccountTokenFilterPolicy" -> to access a specific key
  }

  else
  {
     echo "Creating LocalAccountTokenFilterPolicy"
     New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -Name "LocalAccountTokenFilterPolicy" -Value "1"  -PropertyType "DWORD"
     echo "LocalAccountTokenFilterPolicy has been set"
     Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ | findstr LocalAccountTokenFilterPolicy # -name "LocalAccountToken" -> to access a specific key
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
  
  
 

#https://telaeris.com/kb/wmi-access-denied-asynchronous-calls/
  if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$name`"" -Verb RunAs; exit } 
    netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" dir=in profile=public,private new enable=Yes
    netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" dir=in profile=public,private new enable=Yes
    netsh advfirewall firewall set rule name="Windows Management Instrumentation (ASync-In)" dir=in profile=public,private new enable=Yes
    netsh advfirewall firewall set rule name="Windows Management Instrumentation (DCOM-In)" dir=in profile=public,private new enable=Yes
    netsh advfirewall firewall set rule name="Windows Management Instrumentation (WMI-In)" dir=in profile=public,private new enable=Yes
    netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=yes 
    echo "Setting WIFI to private"
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
    #rules enable = yes
  echo "Exiting..."

}




function disable{
  echo "Stopping remote registry service"

 

  Stop-Service -InputObject (Get-Service -Name RemoteRegistry) -ErrorAction Stop

  echo "-------------------------------------------------------------------------"

  echo "Setting NC_PersonalFirewallConfig to 0 (Enable) "

  Set-ItemProperty -Path 'HKLM:Software\Policies\Microsoft\Windows\Network Connections' -Name "NC_PersonalFirewallConfig" -Value "0" 

  Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -name LocalAccountTokenFilterPolicy -Value "0"
  echo "LocalAccountTokenFilterPolicy cleared.."
 
 
  Clear-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ -Name "RequiredPrivileges" 

 

  Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ -name forceguest -Value "1"
  echo "forceguest cleared.."



  

  if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$name`"" -Verb RunAs; exit } 
    netsh advfirewall firewall set rule name="File and Printer Sharing (NB-Session-In)" dir=in profile=public,private new enable=No
    netsh advfirewall firewall set rule name="File and Printer Sharing (SMB-In)" dir=in profile=public,private new enable=No
    netsh advfirewall firewall set rule name="Windows Management Instrumentation (ASync-In)" dir=in profile=public,private new enable=No
    netsh advfirewall firewall set rule name="Windows Management Instrumentation (DCOM-In)" dir=in profile=public,private new enable=No
    netsh advfirewall firewall set rule name="Windows Management Instrumentation (WMI-In)" dir=in profile=public,private new enable=No
    netsh advfirewall firewall set rule group="windows management instrumentation (wmi)" new enable=No
    
    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public
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
