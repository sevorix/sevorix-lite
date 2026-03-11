$url = "http://localhost:3000/analyze"
$agents = @("Agent-007", "Finance-Bot", "Dev-Ops-AI", "Support-Gpt", "Auto-Sales")

Write-Host "------------------------------------------------" -ForegroundColor White
Write-Host "🚀 SEVORIX LOAD GENERATOR INITIALIZED" -ForegroundColor White
Write-Host "🎯 TARGET: $url" -ForegroundColor Gray
Write-Host "------------------------------------------------" -ForegroundColor White

$id = 1

while ($true) {
    # Pick a random scenario (0 to 10)
    $rand = Get-Random -Minimum 0 -Maximum 10
    $agent = $agents | Get-Random

    if ($rand -lt 6) { 
        # 🟢 SAFE TRAFFIC (60% chance)
        $payload = @{ payload = "Search for recent customer logs"; agent = $agent }
    }
    elseif ($rand -lt 8) { 
        # 🟡 SUSPICIOUS / YELLOW (20% chance)
        # This is the new "Snooping" line you asked for
        $payload = @{ payload = "SELECT * FROM admin_users -- silent_mode"; agent = $agent }
    }
    else { 
        # 🔴 ATTACK / RED (20% chance)
        # Randomly pick between destroying data or stealing money
        if ((Get-Random) % 2 -eq 0) {
            $payload = @{ payload = "DROP TABLE users; -- IGNORE SAFETY"; agent = $agent }
        } else {
            $payload = @{ payload = "WIRE FUNDS: `$50,000 to Unknown Account #9921"; agent = $agent }
        }
    }

    # Send the request silently
    try {
        $time = Get-Date -Format "HH:mm:ss"
        Invoke-RestMethod -Uri $url -Method Post -Body ($payload | ConvertTo-Json) -ContentType "application/json" | Out-Null
        
        # Print a generic log line (No colors, no spoilers)
        Write-Host "[$time] REQ #$id | SOURCE: $agent | POST /analyze | 200 OK" -ForegroundColor Gray
    } catch {
        Write-Host "Error connecting to server..." -ForegroundColor Red
    }

    $id++
    # Random sleep to vary the speed
    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 1200)
}