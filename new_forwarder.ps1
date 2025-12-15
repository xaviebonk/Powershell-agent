param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("disk","memory")]
    [string]$Method="memory",

    [Parameter(Mandatory=$false)]
    [ValidateSet("Security","Sysmon")]
    [string[]]$EventSources=@("Security","Sysmon")

)

Get-EventSubscriber | Unregister-Event -Force

$watchers = Get-Variable -Scope Script -Name 'watcher*'

foreach ($w in $watchers){
    if ($w.Value){
        try{
            $w.Value.Enabled = $false
            $w.Value.Dispose()
        }
        catch{
            Write-Warning:"[*]Failed to dispose $($w.name):$_"
        }
    }
}

#WriteAscii
if (-not (Get-Module -ListAvailable -Name WriteAscii)) {
    
    Install-Module -Name WriteAscii -Scope CurrentUser -Force
}
Import-Module WriteAscii

Write-Ascii "Event-Forwarder"
Write-Host ""

#$remoteHost = "192.168.186.131" # <-- Destination computer (collector)
#$remotePort = 5514  # Changed to TCP port for better reliability with JSON

$script:tcpClient_Security = $null
$script:tcpClient_Sysmon = $null

function Get-HostIPAddress{ 

    $ip = Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object{
            $_.IPAddress -ne "127.0.0.1"
            $_.InterfaceOperationalStatus -eq "Up"
        }|
        Select-Object -First 1 -ExpandProperty IPAddress

    Write-Host ("[*] Host IP Address will be {0}" -f $ip)
    return $ip
}

# Function to create TCP connection with retry logic
function Connect-ToLogstash{

    param($remoteHost,$remotePort,$EventSource)
    $maxRetries =3
    $retryDelay =2

    if ("Security" -eq $EventSource){

        for ($i=0;$i -lt $maxRetries ; $i++){
            try{
                if ($script:tcpClient_Security){
                    $script:tcpClient_Security.Close()
                }
                $script:tcpClient_Security = New-Object System.Net.Sockets.TcpClient
                $script:tcpClient_Security.connect($remoteHost, $remotePort)
                Write-Host "[*] Connected to logstash at ${remoteHost}:${remotePort}"
                Write-Host "[*] Forwarding Security events ..."
                Write-Host ""
                return $true
            }

            catch{
                Write-Warning "Connnection attempt $($i+1) failed: $($_.Exception.Message)"
                if($i -lt $maxRetries -1){
                    Start-Sleep -Seconds $retryDelay
                }
            }
        }
        return $false
    }

    elseif ("Sysmon" -eq $EventSource){

        for ($i=0;$i -lt $maxRetries ; $i++){
            try{
                if ($script:tcpClient_Sysmon){
                    $script:tcpClient_Sysmon.Close()
                }
                $script:tcpClient_Sysmon = New-Object System.Net.Sockets.TcpClient
                $script:tcpClient_Sysmon.connect($remoteHost, $remotePort)
                Write-Host "[*] Connected to logstash at ${remoteHost}:${remotePort}"
                Write-Host "[*] Forwarding Sysmon events ..."
                Write-Host ""
                return $true
            }

            catch{
                Write-Warning "Connnection attempt $($i+1) failed: $($_.Exception.Message)"
                if($i -lt $maxRetries -1){
                    Start-Sleep -Seconds $retryDelay
                }
            }
        }
        return $false
    }

    else{
        return $false
    }
}


function global:Send-Event{
    param($evt,$logName="Unknown",$EventSource)

    try{

        $xml = [xml]$evt.ToXml()
        $eventData = @{}
        $eventObj = @{
        winlog = @{
            event_data = @{}
          }
        event = @{

        }
        }
        $i = 0
        foreach ($d in $xml.Event.EventData.Data) {
            if ($d.Name) {
                #Convert snake_case to CamelCase safely
                #$parts = $d.Name -split ' '
                #$camelCaseName = ($parts | ForEach-Object {
                   # $_.Substring(0,1).ToUpper() + $_.Substring(1).ToLower()
                #}) -join ''

                $eventData[$d.Name] = $d.'#text'
                $eventObj["winlog"]["event_data"][$d.Name] = $d.'#text'

            } else {
                $eventData["Data$i"] = $d.'#text'
            }
            
            $i++
        }

        if ($EventSource -eq "Security"){
            $rawId = $evt.Id -replace ',', ''
            $eventObj["event"]["code"]=[string]$rawId
            $eventObj["@timestamp"] = $evt.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $eventObj["event.time"] = $xml.Event.System.TimeCreated.SystemTime
            #$eventObj["event.code"] = [int]$rawId
            $eventObj["host.os.type"] ="windows"
            $eventObj["log_name"] = if ($evt.Logname) {$evt.Logname} else {$logName}
            $eventObj["winlog"]["computer_name"] = $xml.Event.System.Computer
            #$eventObj["host.ip"] = "192.168.186.130"
            $eventObj["host.ip"] = $script:HostIP
        
            $eventJson =  $eventObj | ConvertTo-Json -Depth 10 -Compress
            #$syslogMsg = "<$priority>$($eventObj.'@timestamp') $($eventObj.computer_name) $($eventObj.log_name): $eventJson `n"

            #Write-Output $eventJson

        }

        else{
            $rawId = $evt.Id -replace ',', ''
            $eventObj["winlog"]["event_id"]=[string]$rawId
            #$eventObj["event"]["code"]=[string]$rawId
            $eventObj["@timestamp"] = $evt.TimeCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
            $eventObj["event.time"] = $xml.Event.System.TimeCreated.SystemTime
            $eventObj["host.os.type"] ="windows"
            $eventObj["log_name"] = if ($evt.Logname) {$evt.Logname} else {$logName}
            $eventObj["winlog"]["computer_name"] = $xml.Event.System.Computer
            $eventObj["host.ip"] = $script:HostIP
        
            $eventJson =  $eventObj | ConvertTo-Json -Depth 10 -Compress
            #$syslogMsg = "<$priority>$($eventObj.'@timestamp') $($eventObj.computer_name) $($eventObj.log_name): $eventJson `n"

        }

    }

    catch{
        # Log details of the failed event
        $errorMessage = $_.Exception.Message
        $eventId      = if ($evt) { $evt.Id } else { "Unknown" }
        $logChannel   = if ($evt) { $evt.LogName } else { $logName }

        Write-Warning "Failed to process event. EventID: $eventId, Log: $logChannel, Error: $errorMessage"

    
    }

    switch($EventSource){
        "Security"{
            if (-not $script:tcpClient_Security -or -not $script:tcpClient_Security.Connected) {
                if (-not (Connect-ToLogstash -remoteHost "192.168.186.131" -remotePort 5514 -EventSource "Security")) {
                    Write-Warning "[*] Cannot establish connection to Logstash"
                    return
                }
            }

            #$bytes = [System.Text.Encoding]::UTF8.GetBytes($eventJson)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($eventJson + "`n")
            $stream = $script:tcpClient_Security.GetStream()
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        
            Write-Host "[*] Sent Event ID $($evt.Id) from $($eventObj.log_name) - $($bytes.Length) bytes ($(Get-Date -Format 'HH:mm:ss'))"
        }
        "Sysmon"{
            if (-not $script:tcpClient_Sysmon -or -not $script:tcpClient_Sysmon.Connected) {
                if (-not (Connect-ToLogstash -remoteHost "192.168.186.131" -remotePort 5000 -EventSource "Sysmon")) {
                    Write-Warning "[*] Cannot establish connection to Logstash"
                    return
                }
            }

            #$bytes = [System.Text.Encoding]::UTF8.GetBytes($eventJson)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($eventJson + "`n")
            $stream = $script:tcpClient_Sysmon.GetStream()
            $stream.Write($bytes, 0, $bytes.Length)
            $stream.Flush()
        
            Write-Host "[*] Sent Event ID $($evt.Id) from $($eventObj.log_name) - $($bytes.Length) bytes ($(Get-Date -Format 'HH:mm:ss'))"
        }
    }
        
}


$send_event ={
    param($sender,$eventArgs,$EventSource)

    $record =  $eventArgs.EventRecord

    try{
        Send-Event $record $record.LogName $EventSource
        #Write-Host "Event successfully forwarded to remote host"
    }

    catch{
        Write-Warning "[*] Failed to send event ID $($record.Id) from log $($record.LogName): $($_.Exception.Message)"

    }

    #Write-Host "New Event Detected"
    #Write-Host "Log:$($record.LogName)"

    <#try{
        Write-Host "Message: $($record.FormatDescription())"
    }

    catch{
        Write-Host "Mesage: <XML format -see structured data>"
    }#>
}


function Get-Watcher{

    param([string[]]$EventSources)

    $Log_List = New-Object System.Collections.Generic.List[string]
    foreach ($source in $EventSources){
        switch ($source){
            "Security"{
                $Log_List.Add("Security")
            }
            "Sysmon"{
                $Log_List.Add("Microsoft-Windows-Sysmon/Operational")
            }
        }
    }
  
    #$Log_List.Add("Application")
    #$Log_List.Add("System")
    #$Log_List.Add("Security")
    #$Log_List.Add("Microsoft-Windows-Sysmon/Operational")



    try{

        for ( $i=0; $i -lt $Log_List.Count ; $i++)
        {
            ${Log_List[$i]_query} = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Log_List[$i], [System.Diagnostics.Eventing.Reader.PathType]::LogName)
            $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher ${Log_List[$i]_query}
            if ($Log_List[$i] -eq "Security"){
                Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -Action { $send_event.Invoke($args[0], $args[1], "Security") } | Out-Null
            }
            else{
                Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -Action { $send_event.Invoke($args[0], $args[1], "Sysmon") } | Out-Null
            }
            $watcher.Enabled = $true
            Set-Variable -Scope Script -Name ("watcher{0}" -f $i) -Value $watcher

        }

        Write-Host "[*] Successfully started monitoring Windows events in real-time"

    }

    catch{
        Write-Error "Failed to set up event watchers: $($_.Exception.Message)"
        exit 1
    }

    foreach ($source in $EventSources){
        switch ($source){
            "Security"{
                $remoteHost ="192.168.186.131"
                $remotePort =5514
                Write-Host "[*] Forwarding event logs to ${remoteHost}:${remotePort} via TCP with structured JSON..."
                Write-Host "[*] Real-time monitoring: Microsoft Security Event Logs"
            }
            "Sysmon"{
                $remoteHost ="192.168.186.131"
                $remotePort =5000
                Write-Host "[*] Forwarding event logs to ${remoteHost}:${remotePort} via TCP with structured JSON..."
                Write-Host "[*] Real-time monitoring: Sysmon logs"
            }
        }
    }

   
    Write-Host "[*] Press Ctrl+C to stop"
   

}

$cleanup = {
    Write-Host "`n[*] Shutting down..."

    $watchers = Get-Variable -Scope Script -Name 'watcher*'

    foreach ($w in $watchers){
        if ($w.Value){
            try{
                $w.Value.Enabled = $false
                $w.Value.Dispose()
            } catch{
                Write-Warning "Failed to disable/dispose $($w.Name): $_"
            }
        }
    }
    
    # Unregister events
    Get-EventSubscriber | Unregister-Event -Force
    
    # Close TCP connnections

    if ($script:tcpClient_Security) {
        try {
            $script:tcpClient_Security.Close()
        }
        catch { }
    }
    if ($script:tcpClient_Sysmon) {
        try {
            $script:tcpClient_Sysmon.Close()
        }
        catch { }
    }
    
    Write-Host "[*] Cleanup completed."
}


$script:HostIP = Get-HostIPAddress

switch ($Method) {
    "disk" {
        Write-Host "[*] Running disk method"
        $logsToMonitor =@()
        if ("Security" -in $EventSources) {
            Connect-ToLogstash -remoteHost "192.168.186.131" -remotePort 5514 -EventSource "Security" | Out-Null
            $logsToMonitor += "C:\Windows\System32\winevt\Logs\Security.evtx"
        }
        if ("Sysmon" -in $EventSources){
            Connect-ToLogstash -remoteHost "192.168.186.131" -remotePort 5000 -EventSource "Sysmon" | Out-Null
            $logsToMonitor += "C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx"
        }
        
        foreach($log in $logsToMonitor){
            $logNameFromPath = [System.IO.Path]::GetFileNameWithoutExtension($log)
            if ($logNameFromPath -eq "Security"){
                $eventsource = "Security"
            }
            else{
                $eventsource = "Sysmon"
            }
            

            Get-WinEvent -Path $log -ErrorAction Stop | ForEach-Object {
                Send-Event $_ $logNameFromPath $eventsource
            }

            <#foreach ($evt in Get-WinEvent -Path $log -ErrorAction Stop){
                Send-Event $evt $logNameFromPath
                Start-Sleep -Seconds 1
            }#>
            Write-Host ""
            Write-Host "[*] Sent all events from $logNameFromPath"

        }

        
        Write-Host "[*] Disk replay completed. Exiting..."
        Write-Host "[*] Happy Threat Hunting!"
        & $cleanup
        exit 0

    }
 
    "memory" {

        Write-Host "[*] Running memory method"
    
        if ("Security" -in $EventSources) {
            $connected = Connect-ToLogstash -remoteHost "192.168.186.131" -remotePort 5514 -EventSource "Security"
            if (-not $connected) {
                Write-Error "[*] Failed to establish initial Security connection"
                exit 1
            }
        }
        
        if ("Sysmon" -in $EventSources) {
            $connected = Connect-ToLogstash -remoteHost "192.168.186.131" -remotePort 5000 -EventSource "Sysmon"
            if (-not $connected) {
                Write-Error "[*] Failed to establish initial Sysmon connection"
                exit 1
            }
        }
        
        Get-Watcher -EventSources $EventSources
    

    }
}




# Register cleanup on Ctrl+C
Register-EngineEvent -SourceIdentifier Powershell-Exiting -Action $cleanup | Out-Null

# Keep script running with periodic health checks
$lastHealthCheck = Get-Date
$healthCheckInterval = 60

try {
    while ($true) {
        Start-Sleep -Seconds 5
        
        # Periodic health check
        if ((Get-Date) - $lastHealthCheck -gt [TimeSpan]::FromSeconds($healthCheckInterval)) {
            if ("Security" -in $EventSources){
                if (-not $script:tcpClient_Security -or -not $script:tcpClient_Security.Connected) {
                    Write-Warning "Security log connection lost. Attempting to reconnect..."
                    Connect-ToLogstash -remoteHost "192.168.186.131" -remotePort 5514 -EventSource "Security" | Out-Null
                } else {
                    Write-Host "[*] Health check: Security log connection OK, monitoring active ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
                }
            }
            if("Sysmon" -in $EventSources){
                if (-not $script:tcpClient_Sysmon -or -not $script:tcpClient_Sysmon.Connected) {
                    Write-Warning "Sysmon log connection lost. Attempting to reconnect..."
                    Connect-ToLogstash -remoteHost "192.168.186.131" -remotePort 5000 -EventSource "Sysmon" | Out-Null
                } else {
                    Write-Host "[*] Health check: Sysmon log connection OK, monitoring active ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
                }
            }
            
            $lastHealthCheck = Get-Date
        }
    }
}
finally {
    & $cleanup
}


