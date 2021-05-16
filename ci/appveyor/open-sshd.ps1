# Partially copied from https://github.com/appveyor/ci/blob/master/scripts/enable-rdp.ps1

# get current IP
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -like 'ethernet*'}).IPAddress
$port = 3389
if($ip.StartsWith('172.24.')) {
    $port = 33800 + ($ip.split('.')[2] - 16) * 256 + $ip.split('.')[3]
} elseif ($ip.StartsWith('192.168.') -or $ip.StartsWith('10.240.')) {
    # new environment - behind NAT
    $port = 33800 + ($ip.split('.')[2] - 0) * 256 + $ip.split('.')[3]
} elseif ($ip.StartsWith('10.0.')) {
    $port = 33800 + ($ip.split('.')[2] - 0) * 256 + $ip.split('.')[3]
}

# get external IP
$extip = (New-Object Net.WebClient).DownloadString('https://www.appveyor.com/tools/my-ip.aspx').Trim()

# allow inbound traffic
New-NetFirewallRule -DisplayName "SSH and RDP" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22,3389

# configure port forwarding from RDP port to SSH server
netsh interface portproxy add v4tov4 listenport=3389 listenaddress=$ip connectport=22 connectaddress=127.0.0.1
netsh interface portproxy show all

# check if SSH server is running
ps sshd

# print SSH server connection info
Write-Host "$extip`:$port" -ForegroundColor Gray
