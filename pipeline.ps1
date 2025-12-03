Get-EventSubscriber | Unregister-Event -Force

$watchers = Get-Variable -Scope Script -Name 'watcher*'

foreach ($w in $watchers){
    if ($w.Value){
        try{
            $w.Value.Enabled = $false
            $w.Value.Dispose()
        }
        catch{
            Write-Warning:"Failed to dispose $($w.name):$_"
        }
    }
}

$tcpClient = $null
$remoteHost = "192.168.186.131"
$remotePort = 5503

function Connect-ToLogstash{
    $maxRetries =5
    $retryDelay =2

    for ($i=0;$i -lt $maxRetries ; $i++){
        try{
            if ($script:tcpClient){
                $script:tcpClient.Close()
            }
            $script:tcpClient = New-Object System.Net.Sockets.TcpClient
            $script:tcpClient.connect($remoteHost, $remotePort)
            Write-Host "Connected to logstash at ${remoteHost}:${remotePort}"
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


# Create TCP client (reuse connection)

# In your event handler
function onEvent {
    param($sender, $eventArgs)

    $event = $eventArgs.EventRecord

    try {
        # Convert event to PowerShell object
        $eventObj = $event | Select-Object -Property *

        # Convert to JSON
        $json = $eventObj | ConvertTo-Json -Depth 20

        # Convert JSON to bytes and send to Logstash
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush()

        Write-Host "Sent EventID $($event.Id) to Logstash" -ForegroundColor Green
    }
    catch {
        Write-Host "Error sending event: $_" -ForegroundColor Red
    }
}


$send_event ={

    param($sender,$eventArgs)

    $record =  $eventArgs.EventRecord

    try{
        Send-Event $record $record.LogName
        Write-Host "Event successfully forwarded to remote host"
    }

    catch{
        Write-Warning "Failed to send event ID $($record.Id) from log $($record.LogName): $($_.Exception.Message)"

    }

    Write-Host "New Event Detected"
    Write-Host "Log:$($record.LogName)"

    try{
        Write-Host "Message: $($record.FormatDescription())"
    }

    catch{
        Write-Host "Mesage: <XML format -see structured data>"
    }

}


#List to create watchers for security events

$Log_List = New-Object System.Collections.Generic.List[string]
#$Log_List.Add("Application")  Monitoring for application and system logs should not be neccessary in this case since Winlog does not have a pipeline for this.
#$Log_List.Add("System")
$Log_List.Add("Security")


try{

    for ( $i=0; $i -lt $Log_List.Count ; $i++)
    {
        ${Log_List[$i]_query} = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery($Log_List[$i], [System.Diagnostics.Eventing.Reader.PathType]::LogName)
        $watcher = New-Object System.Diagnostics.Eventing.Reader.EventLogWatcher ${Log_List[$i]_query}
        Register-ObjectEvent -InputObject $watcher -EventName EventRecordWritten -Action $send_event | Out-Null
        $watcher.Enabled = $true
        Set-Variable -Scope Script -Name ("watcher{0}" -f $i) -Value $watcher

    }

    Write-Host "Successfully started monitoring Windows events in real-time"

}

catch{
    Write-Error "Failed to set up event watchers: $($_.Exception.Message)"
    exit 1
}

Write-Host "Forwarding event logs to ${remoteHost}:${remotePort} via TCP with structured JSON..."
Write-Host "Initial events sent from: Security, Application, System logs"
Write-Host "Real-time monitoring: Security, Application and System logs"
Write-Host "Press Ctrl+C to stop"

$cleanup = {
    Write-Host "`nShutting down..."

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
    
    # Close TCP connection
    if ($script:tcpClient) {
        try {
            $script:tcpClient.Close()
        }
        catch { }
    }
    
    Write-Host "Cleanup completed."
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
            if (-not $script:tcpClient -or -not $script:tcpClient.Connected) {
                Write-Warning "Connection lost. Attempting to reconnect..."
                Connect-ToLogstash | Out-Null
            } else {
                Write-Host "Health check: Connection OK, monitoring active ($(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))"
            }
            $lastHealthCheck = Get-Date
        }
    }
}
finally {
    & $cleanup
}


