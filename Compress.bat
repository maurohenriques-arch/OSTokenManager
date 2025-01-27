del ".\Binaries\TokenManager.zip"
powershell Compress-Archive -Path ".\TokenManager\bin\Release\net8.0\linux-x64\publish\*" -DestinationPath ".\Binaries\TokenManager"
readline()