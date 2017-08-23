# netscan.ps1
# this script performs a detailed network scan to identify active devices, retrieve MAC addresses,
# scan for open ports across a wider range, and output results with device information.

# get the local IP address and subnet mask to figure out the network range
function Get-NetworkRange {
    $ipconfig = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }
    $ipAddress = $ipconfig.IPAddress
    $subnetMask = $ipconfig.PrefixLength
    $networkRange = "$ipAddress/$subnetMask"
    return $networkRange
}

# function to scan the network for active devices, retrieving IPs and hostnames
function Scan-Network {
    param (
        [string]$networkRange
    )

    Write-Host "scanning network range: $networkRange"
    $ipBase = $networkRange -replace '\d+$', ''
    $activeDevices = @()

    for ($i = 1; $i -le 254; $i++) {
        $ip = "$ipBase$i"
        if (Test-Connection -ComputerName $ip -Count 1 -Quiet) {
            $hostname = (Resolve-DnsName -Name $ip -ErrorAction SilentlyContinue).NameHost
            if (-not $hostname) { $hostname = "Unknown" }
            $activeDevices += [PSCustomObject]@{
                IPAddress = $ip
                Hostname = $hostname
            }
            Write-Host "$ip is active (Hostname: $hostname)"
        }
    }
    return $activeDevices
}

# function to retrieve MAC addresses using arp
function Get-MACAddress {
    param (
        [array]$activeDevices
    )

    Write-Host "`nretrieving MAC addresses for active devices..."
    $arpTable = arp -a

    foreach ($device in $activeDevices) {
        $ip = $device.IPAddress
        $mac = ($arpTable | Select-String $ip).ToString().Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)[1]
        if ($mac) {
            $device | Add-Member -MemberType NoteProperty -Name MACAddress -Value $mac
            Write-Host "$ip - Hostname: $($device.Hostname), MAC Address: $mac"
        } else {
            Write-Host "$ip - Hostname: $($device.Hostname), MAC Address: Not found"
        }
    }
}

# function to check a range of ports on each active device
function Check-OpenPorts {
    param (
        [array]$activeDevices
    )

    $commonPorts = @{
        21  = "FTP: File Transfer Protocol"
        22  = "SSH: Secure Shell"
        23  = "Telnet: Unencrypted remote login"
        25  = "SMTP: Simple Mail Transfer Protocol"
        53  = "DNS: Domain Name System"
        80  = "HTTP: Hypertext Transfer Protocol"
        110 = "POP3: Post Office Protocol version 3"
        143 = "IMAP: Internet Message Access Protocol"
        443 = "HTTPS: HTTP Secure"
        3389 = "RDP: Remote Desktop Protocol"
        8080 = "HTTP-Alt: Alternative HTTP protocol"
    }

    Write-Host "`nscanning for open ports on active devices..."
    foreach ($device in $activeDevices) {
        Write-Host "`n$($device.IPAddress) - Hostname: $($device.Hostname), MAC: $($device.MACAddress)"
        $devicePorts = @()
        
        foreach ($port in $commonPorts.Keys) {
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $tcpClient.Connect($device.IPAddress, $port)
                $tcpClient.Close()
                $devicePorts += "$port: $($commonPorts[$port])"
                Write-Host "Port $port is open - $($commonPorts[$port])"
            } catch {
                # port is closed, no action needed
            }
        }

        # add open ports info to device object
        if ($devicePorts) {
            $device | Add-Member -MemberType NoteProperty -Name OpenPorts -Value ($devicePorts -join ", ")
        } else {
            $device | Add-Member -MemberType NoteProperty -Name OpenPorts -Value "No open common ports"
        }
    }
}

# main script execution: get network range, scan for devices, retrieve MACs, and check open ports
$networkRange = Get-NetworkRange
$activeDevices = Scan-Network -networkRange $networkRange
Get-MACAddress -activeDevices $activeDevices
Check-OpenPorts -activeDevices $activeDevices