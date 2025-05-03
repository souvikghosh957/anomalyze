$pcap_dir = "C:\Users\souvi\zeek_logs\zeek-networkfiles"
$processed_dir = "$pcap_dir\processed"

# Create processed directory if it doesn't exist
if (!(Test-Path -Path $processed_dir)) {
    New-Item -ItemType Directory -Path $processed_dir
}

# List of log files to sort (customize this as needed)
$log_files_to_sort = @("conn.log", "dns.log", "ssl.log", "http.log", "files.log", "auth.log", "notice.log", "ssh.log")

Write-Host "Zeek log processor started. Checking for new .pcap files every 1 minute..."

while ($true) {
    $pcap_files = Get-ChildItem -Path $pcap_dir -Filter "*.pcap"

    foreach ($file in $pcap_files) {
        $pcap_file = $file.FullName
        $filename = $file.BaseName  # Get file name without extension
        $output_dir = "$processed_dir\$filename"

        # Check if this file has already been processed
        if (Test-Path "$output_dir") {
            Write-Host "Skipping $pcap_file (already processed)"
            continue
        }

        # Create a separate folder for each processed file
        New-Item -ItemType Directory -Path $output_dir -Force | Out-Null

        # Run Zeek in Docker
        Write-Host "Processing $pcap_file..."

        # Construct the Docker command
        $docker_command = "docker run --rm -v ${pcap_dir}:/zeek_logs -w /zeek_logs zeek/zeek zeek -C -e 'redef LogAscii::use_json=T;' -r /zeek_logs/$($file.Name) Log::default_logdir='/zeek_logs/processed/$filename'"

        # Print and execute the Docker command
        Write-Host "Running Docker command: $docker_command"
        Invoke-Expression $docker_command

        Write-Host "Processed logs saved in $output_dir"

        # Sort the specified log files
        foreach ($log_file in $log_files_to_sort) {
            $input_log = "$output_dir\$log_file"
            # Fix the sorted log file name
            $sorted_log = "$output_dir\$($log_file -replace '\.log$', '_sorted.log')"

            if (Test-Path $input_log) {
                Write-Host "Sorting $log_file..."
                # Call the Python script to sort the log
                python sort_zeek_json.py $input_log $sorted_log
                Write-Host "Sorted log saved as $sorted_log"
            } else {
                # Improved message for clarity
                Write-Host "Log file $log_file not generated for $filename, skipping."
            }
        }
    }

    # Wait for 1 minute before checking again
    Start-Sleep -Seconds 60
}