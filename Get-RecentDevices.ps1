# PowerShell script to retrieve devices with sign-ins in the last 24 hours
# Filters by naming pattern 'XXX-Y-ZZZZZZZ' and exports to CSV

# Connect to Microsoft Graph
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Green
Connect-MgGraph -Scopes "Device.Read.All", "User.Read.All" | Out-Null
Write-Host "Successfully connected to Microsoft Graph" -ForegroundColor Green

# Define the naming pattern: XXX-Y-ZZZZZZZ
# This regex matches: 3 chars - 1 char - 7 chars
$namingPattern = "^.{3}-.-{7}$"

# Calculate timestamp for last 24 hours
$twentyFourHoursAgo = (Get-Date).AddHours(-24)

Write-Host "Retrieving devices..." -ForegroundColor Green

# Get all devices
$devices = Get-MgDevice -All -Property "Id,DisplayName,ApproximateLastSignInDateTime" -ErrorAction SilentlyContinue

# Filter devices by:
# 1. Last sign-in within last 24 hours
# 2. Naming pattern matching XXX-Y-ZZZZZZZ
$filteredDevices = $devices | Where-Object {
    ($_.ApproximateLastSignInDateTime -gt $twentyFourHoursAgo) -and
    ($_.DisplayName -match $namingPattern)
}

Write-Host "Found $($filteredDevices.Count) devices matching criteria" -ForegroundColor Green

# Build result array with device info and associated user
$results = @()

foreach ($device in $filteredDevices) {
    # Get the registered owner (user) of the device
    try {
        $owner = Get-MgDeviceRegisteredOwner -DeviceId $device.Id -ErrorAction SilentlyContinue
        $userName = $owner.UserPrincipalName

        if (-not $userName) {
            $userName = $owner.DisplayName
        }
        if (-not $userName) {
            $userName = "Unknown"
        }
    }
    catch {
        $userName = "Unknown"
    }

    # Create result object
    $result = [PSCustomObject]@{
        "Device Name" = $device.DisplayName
        "User" = $userName
        "Sign-In DateTime" = $device.ApproximateLastSignInDateTime
    }

    $results += $result
}

# Define CSV output path
$csvPath = ".\RecentDevices_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

# Export to CSV
if ($results.Count -gt 0) {
    $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to: $csvPath" -ForegroundColor Green
    Write-Host "Total devices: $($results.Count)" -ForegroundColor Green
}
else {
    Write-Host "No devices found matching the criteria" -ForegroundColor Yellow
}

# Display results in console
$results | Format-Table -AutoSize
