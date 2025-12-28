@echo off
color 0f
cls
echo Terminal ready...

set tapeFilePath="%CD%\readme.tape"

vhs.exe %tapeFilePath%