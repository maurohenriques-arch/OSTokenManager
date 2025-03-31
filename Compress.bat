@echo off
ECHO Deleting old archive if it exists...
DEL /Q ".\Binaries\TokenManager.zip"

ECHO Creating new archive...
powershell -Command "Compress-Archive -Path '.\TokenManager\bin\Release\net8.0\linux-x64\publish\*' -DestinationPath '.\Binaries\TokenManager.zip' -Force"

ECHO Done.