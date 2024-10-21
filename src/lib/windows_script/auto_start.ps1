$binaryPath = "C:\Path\To\rusty_agent.exe"
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
New-ItemProperty -Path $registryPath -Name "MyBinary" -Value $binaryPath -PropertyType String -Force | Out-Null
Write-Host "Binary added to auto-start on Windows startup."

