# Specify the filename to search for
$fileName = "T10_MS_Combined.bk2"

# Get all logical drives on the system
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }

# Iterate over each drive
foreach ($drive in $drives) {
    $driveLetter = $drive.Name

    # Search for the file in the current drive
    $filePaths = Get-ChildItem -Path "$driveLetter\*" -Filter $fileName -File -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName

    # Process the file paths found
    foreach ($filePath in $filePaths) {
        Write-Host "File found: $filePath"
        
        # Change directory to the folder containing the file
        $folderPath = Split-Path -Path $filePath -Parent
        Set-Location -Path $folderPath
        
        # Perform additional actions within the folder as needed
        # ...
        Get-ChildItem * -Include T10_MS_Combined.bk2 -Recurse | Remove-Item
    }
}