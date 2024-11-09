Set-ExecutionPolicy Unrestricted -Scope Process


# Set list of targets"
$targetList = @(
    "192.168.1.1",
    "192.168.2.2",
    "192.168.3.3"
)

# Set of common ports
$common = @(
	7,20,21,22,23,
	25,53,69,80,88,
	102,110,135,137,
	138,139,143,381,
	383,443,445,464,
	587,593,636,691,
	902,989,995,1025,3389,
	1194,1337,1433,2179,
	4022,1434,1589,1725,
	1900,5353,5780,3702,
	2083,2483,2484,2967,
	3074,3306,3724,4664,
	5432,5900,6665,6666,
	6667,6668,6669,6881,
	6999,6970,8080,8081,
	8082,8087,8222,9100,
	10000,12345,27374,31337
)

$sample= @(
	135, 3389, 2179, 445, 139
)

$allports = 1..65535

#$h = $args[0]

# Store ips and ports
$ipPortDict = @{}

$suppressClosedPorts = "true"

Function smtp_portscan
{
	Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $target,
         [Parameter(Mandatory=$true, Position=1)]
         [int] $port
    )
    $t = $target + ":" + $port
    
    try
    {
	    $resp = Send-MailMessage -To "recipient@example.com" -From "sender@example.com" -Subject "subject" -Body "body" -SmtpServer $target -Port $port -Verbose -ErrorAction Stop   
    }
    catch
    {
        $resp = $_.Exception.Message
    }

    # enable for debugging
    #Write-Output $resp
    
    if($resp -like "Unable to connect to the remote server" -and $suppressClosedPorts -eq "false")
    {
        Write-Output "[MAIL] $t - closed"
    }
    if($resp -like "The operation has timed out.")
    {
        Write-Output "[MAIL] $t - Open|filtered"
        $ipPortDict[$target] += @($port)
    }
    if($resp -like "Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host.")
    {
        Write-Output "[MAIL] $t - open"
        $ipPortDict[$target] += @($port)
    }
}

Function http_portscan
{
	Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $target,
         [Parameter(Mandatory=$true, Position=1)]
         [int] $port
    )
    $t = $target + ":" + $port
    
    try
    {
	    $resp = Invoke-WebRequest -Uri $t -TimeoutSec 30  
    }
    catch
    {
        $resp = $_.Exception.Message
    }

    # enable for debugging
    #Write-Output $resp
    
    if($resp -like "Unable to connect to the remote server" -and $suppressClosedPorts -eq "false")
    {
        Write-Output "[HTTP] $t - closed"
    }
    if($resp -like "The operation has timed out.")
    {
        Write-Output "[HTTP] $t - open|filtered"
        $ipPortDict[$target] += @($port)
    }
    if($resp -like "Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host.")
    {
        Write-Output "[HTTP] $t - open"
        $ipPortDict[$target] += @($port)
    }
    if($resp -like "The underlying connection was closed: An unexpected error occurred on a receive.")
    {
        Write-Output "[HTTP] $t - open"
        $ipPortDict[$target] += @($port)
    }
}

# WSMAN can differentiate some ports, but might miss some.
Function wsman_portscan
{
	Param
    (
         [Parameter(Mandatory=$true, Position=0)]
         [string] $target,
         [Parameter(Mandatory=$true, Position=1)]
         [int] $port
    )
    $t = $target + ":" + $port
    
    try
    {
	    $resp = Test-WSMan -ComputerName $target -Port $port -Verbose -UseSSL -ErrorAction Stop
    }
    catch
    {
        $resp = $_.Exception.Message
    }

    # enable for debugging
    #Write-Output $resp
    
    if($resp -like "*2150859046*" -and $suppressClosedPorts -eq "false")
    {
        Write-Output "[WSMAN] $t - closed"
    }
    if($resp -like "*12175*")
    {
        Write-Output "[WSMAN] $t - open"
        $ipPortDict[$target] += @($port)
    }
    if($resp -like "*2150859194*")
    {
        Write-Output "[WSMAN] $t - open"
        $ipPortDict[$target] += @($port)
    }
    if($resp -like "*2150858770*" -and $suppressClosedPorts -eq "false")
    {
        Write-Output "[WSMAN] $t - closed"
    }
    if($resp -like "*12005*")
    {
        Write-Output "[WSMAN] $t - Error"
    }
}

#implement restmethod
# works:
#$response = Invoke-RestMethod -Uri "http://127.0.0.1:443" -Method OPTIONS -Headers @{ Authorization = "aaa" }


#Write-Output "SMTP Portscan"
foreach ($port in $common)
{
	$t = $target + ":" + $port
	#Write-Output  $t
	#smtp_portscan -target $target -port $port
}

#Write-Output "HTTP Portscan"
foreach ($port in $common)
{
	$t = $target + ":" + $port
	#Write-Output  $t
	#http_portscan -target $target -port $port
}

#Write-Output "WSMAN Portscan"
foreach ($port in $common)
{
	$t = $target + ":" + $port
	#Write-Output  $t
	#wsman_portscan -target $target -port $port
}


Write-Output "PowerScan - Port Scanner"
Write-Output "Author: Elysee Franchuk (kva55)"
Write-Output "PowerScan - Port Scanner"
foreach ($target in $targetList)
{
    Write-Output ""
    Write-Output "Starting Portscan on $target"
    
    foreach ($port in $sample)
    {

        $c = Get-Random -Minimum 1 -Maximum 4
	
        #$t = $target + ":" + $port
	    #Write-Output  $t
	    if($c -eq 1)
        {
            smtp_portscan -target $target -port $port
            #$c++
        }
        elseif($c -eq 2)
        {
            http_portscan -target $target -port $port
            #$c++
        }
        elseif($c -eq 3)
        {
            wsman_portscan -target $target -port $port
            #$c++
        }
    }
}

# Display all found ports and ip pairs
$ipPortDict
