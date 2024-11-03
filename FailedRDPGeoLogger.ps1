# Get API key from here: https://ipgeolocation.io/
$API_KEY = "your_api_key_here"

$LOGFILE_NAME = "failed_rdp.log"
$LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

# This filter will be used to filter failed RDP events from Windows Event Viewer
$XMLFilter = @'
<QueryList>
    <Query Id="0" Path="Security">
        <Select Path="Security"> *[System[(EventID='4625')]] </Select>
    </Query>
</QueryList>
'@

# Cache for storing geolocation results to avoid redundant API calls
$ipCache = @{}

# Function to get geolocation data with caching
function Get-Geolocation {
    param ($ip)

    if ($ipCache.ContainsKey($ip)) {
        Write-Debug "IP $ip found in cache."
        return $ipCache[$ip]
    } else {
        Write-Debug "IP $ip not found in cache. Fetching from API."
        $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($ip)"
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT
            $responseData = $response.Content | ConvertFrom-Json
            $ipCache[$ip] = $responseData
            Write-Debug "Geolocation data for IP $ip retrieved successfully."
            return $responseData
        } catch {
            Write-Warning "Failed to retrieve geolocation data for IP: $ip"
        }
    }
}

# Create the log file if it doesn't already exist
if ((Test-Path $LOGFILE_PATH) -eq $false) {
    New-Item -ItemType File -Path $LOGFILE_PATH
    Write-Verbose "Log file created at: $LOGFILE_PATH"
}

# Infinite loop that keeps checking the Event Viewer logs.
while ($true) {
    Start-Sleep -Seconds 10  # Adjust sleep time based on your needs
    
    # Retrieve events from Windows Event Viewer based on the filter
    Write-Verbose "Retrieving events from Event Viewer..."
    try {
        $events = Get-WinEvent -FilterXml $XMLFilter -ErrorAction Stop
        Write-Debug "$($events.Count) events retrieved."
    } catch {
        Write-Warning "Failed to retrieve events from Event Viewer."
        continue
    }

    foreach ($event in $events) {
        # Check if the event contains a valid source IP address
        if ($event.properties[19].Value.Length -ge 5) {
            # Extract relevant fields from the event
            $timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            $destinationHost = $event.MachineName # Workstation Name (Destination)
            $username = $event.properties[5].Value # Account Name (Attempted Logon)
            $sourceIp = $event.properties[19].Value # IP Address

            Write-Debug "Processing event with timestamp: $timestamp, source IP: $sourceIp, username: $username"

            # Check if this event has already been logged using Select-String (more efficient)
            if (-Not (Select-String -Path $LOGFILE_PATH -Pattern "$($timestamp)" -Quiet)) {

                # Get geolocation data from cache or API call
                Write-Debug "Fetching geolocation data for IP: $sourceIp"
                try {
                    $geoData = Get-Geolocation -ip $sourceIp

                    # Extract geolocation details
                    if ($geoData) {
                        Write-Debug "Geolocation data received for IP: $sourceIp"
                        $latitude = $geoData.latitude
                        $longitude = $geoData.longitude
                        $state_prov = if ($geoData.state_prov) { $geoData.state_prov } else { "null" }
                        $country = if ($geoData.country_name) { $geoData.country_name } else { "null" }

                        # Write all gathered data to the custom log file.
                        "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                        Write-Host -BackgroundColor Black -ForegroundColor Magenta "Logged: latitude:$($latitude), longitude:$($longitude), username:$($username), sourcehost:$($sourceIp), state:$($state_prov), country:$($country), timestamp:$($timestamp)"
                    } else {
                        Write-Warning "No geolocation data available for IP: $sourceIp"
                    }
                } catch {
                    Write-Warning "Failed to process geolocation data for IP: $sourceIp"
                }

            } else {
                Write-Debug "Event already exists in the custom log. Skipping."
            }
        } else {
            Write-Debug "Invalid source IP address in event. Skipping."
        }
    }
}
