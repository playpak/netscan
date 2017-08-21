# netscan.ps1
# this script performs a basic network scan to find active devices on the local network
# and attempts to retrieve device information, including hostname and MAC address.

# get the local IP address and subnet mask to figure out the network range
function Get-NetworkRange {
    $ipconfig = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" }
    $ipAddress = $ipconfig.IPAddress
    $subnetMask = $ipconfig.PrefixLength
    $networkRange = "$ipAddress/$subnetMask"
    return $networkRange
}

# function to scan the network by pinging each IP in the range
function Scan-Network {
    param (
        [string]$networkRange
    )

    Write-Host "scanning network range: $networkRange"
    
    # split the IP base to loop through addresses 1-254
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

# main script execution
$networkRange = Get-NetworkRange
$activeDevices = Scan-Network -networkRange $networkRange
Get-MACAddress -activeDevices $activeDevices
