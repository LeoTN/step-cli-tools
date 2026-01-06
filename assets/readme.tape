Output readme.gif

Require sct

Set Shell powershell
Set Width 1500
Set Height 750
Set Padding 20

# Start the tool
Type@300ms sct
Enter

Sleep 5s

# Select the first operation
Enter

Sleep 3s

# Enter the server name
Type@200ms my-step-ca-server
Sleep 1s
Enter

Sleep 5s

# Confirm
Type@200ms y

Sleep 5s

# Select the second operation
Down
Sleep 3s
Enter

Sleep 3s

# Enter certificate name wildcard
Type@200ms "*demo*"
Sleep 1s
Enter

Sleep 3s

# Confirm
Type@200ms y

Sleep 5s
