@echo off
color 0f
cls
echo Terminal ready...

set psScriptPath="%CD%\CheckDependencies.ps1"

powershell.exe -executionPolicy bypass -file %psScriptPath%