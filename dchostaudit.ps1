# Import the ActiveDirectory module
Import-Module ActiveDirectory
$filedate = Get-Date -Format "yyyyMMdd"
$logfile = "AuditReport_$filedate.log"

Write-Output "Starting new audit report...`n" | Tee-Object -FilePath $logfile

function Start-WinRM {
    Param (
        [string] $Computer, 
        [System.Management.Automation.PSCredential] $Credential
    )
    try {
        $service = Get-WmiObject -ComputerName $Computer -Credential $Credential -Class Win32_Service -Filter "Name='WinRM'"
        $service.StartService()
        Write-Output "WinRM service started on $Computer"
    } catch {
        Write-Output "Failed to start WinRM service on $Computer. Error: $_"
    }
}

function Get-InstalledSoftware {
    Param (
        [string] $ComputerName
    )
    $32BitPrograms = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $64BitPrograms = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    $AllInstalledSoftware = @($32BitPrograms + $64BitPrograms)
    #Write-Output "Retrieved installed software for $ComputerName"
    return $AllInstalledSoftware
}

# User Credential
$cred = Get-Credential

# Retrieve all computer objects from Active Directory
$computers = Get-ADComputer -Filter *

# Array to store all computer information
$computerInfo = @()

foreach ($computer in $computers) {
    $computerName = $computer.Name
    if ($computerName -eq $env:COMPUTERNAME) {
        Write-Output "Getting IP, MAC addresses, and installed software for $computerName" | Tee-Object -FilePath $logfile -Append
        # Get IP address using WMI locally
        $ipAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }).IPAddress 
        # Get only IPv4 Address using WMI and regex
        #$ipAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }).IPAddress | Where-Object { $_ -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' }
        # Get MAC address using WMI locally
        $macAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -ne $null }).MACAddress
        # Get installed software using the function Get-InstalledSoftware locally
        $installedSoftware = Get-InstalledSoftware -ComputerName $env:COMPUTERNAME 

        # Create custom object with IP, MAC addresses, and installed software
        $hinfo = [PSCustomObject]@{
            ComputerName      = $env:COMPUTERNAME
            IPAddress         = $ipAddress
            MACAddress        = $macAddress
        } | Select-Object ComputerName, IPAddress, MACAddress

        #Combine host info and software list
        $info = $hinfo, $installedSoftware

        # Output to CLI and log file
        Write-Output "Output for $computerName`:" | Tee-Object -FilePath $logfile -Append
        Write-Output $info | Format-List | Tee-Object -FilePath $logfile -Append
    }
    else {
        Write-Output "Starting WinRM on $computerName"
        Start-WinRM -Computer $computerName -Credential $cred > $null

        Write-Output "Getting IP, MAC addresses, and installed software for $computerName" | Tee-Object -FilePath $logfile -Append
        # Use Invoke-Command to run a script block on the remote computer
        $info = Invoke-Command -ComputerName $computerName -Credential $cred -ScriptBlock {
            Param ($computerName)
            function Get-InstalledSoftware {
                Param (
                    [string] $ComputerName
                )
                $32BitPrograms = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
                $64BitPrograms = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
                $AllInstalledSoftware = @($32BitPrograms + $64BitPrograms)
                #Write-Output "Retrieved installed software for $ComputerName"
                return $AllInstalledSoftware
            }
            
            # Get IP address using WMI
            $ipAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }).IPAddress
            # Get only IPv4 Address using WMI and regex
            #$ipAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPAddress -ne $null }).IPAddress | Where-Object { $_ -match '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' }
            # Get MAC address using WMI
            $macAddress = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.MACAddress -ne $null }).MACAddress
            # Get installed software using function Get-InstalledSoftware
            $installedSoftware = Get-InstalledSoftware -ComputerName $env:COMPUTERNAME

            # Create custom object with IP, MAC addresses, and installed software
            $rhinfo = [PSCustomObject]@{
                ComputerName      = $env:COMPUTERNAME
                IPAddress         = $ipAddress
                MACAddress        = $macAddress
            }  | Select-Object ComputerName, IPAddress, MACAddress
            $rinfo = $rhinfo, $installedSoftware
            return $rinfo
        } -ArgumentList $computerName

        # Output to CLI and log file
        Write-Output "Output for $computerName`:" | Tee-Object -FilePath $logfile -Append
        Write-Output $info | Format-List | Tee-Object -FilePath $logfile -Append
    }
    
    # Add computer info to the array
    $computerInfo += $info
}

# Output all collected information to a text file using Format-List for detailed output
$computerInfo | Format-List | Out-File -FilePath "output.txt"


# Also output to the console
#$computerInfo | Format-List

# Convert the information to CSV format and save it to a file
#$computerInfo | Export-Csv -Path "computer_info.csv" -NoTypeInformation
#Write-Host "Output has been saved to computer_info.csv"