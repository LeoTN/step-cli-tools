Output readme.gif

Require powershell
Require sct

Set Shell powershell
Set Width 1500
Set Height 750
Set Padding 20

# Start the tool
Type@300ms sct
Enter

Sleep 5s



# Install root CA certificate operation
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



# Request certificate operation
Down@200ms 2
Sleep 3s
Enter

Sleep 3s

# Enter the server name
Type@200ms my-step-ca-server
Sleep 1s
Enter

Sleep 3s

# Change subject name
Enter
Sleep 3s
Backspace@200ms 9
Sleep 1s
Type@200ms demo.com
Sleep 1s
Enter

Sleep 3s

# Change SAN entries
Down@200ms 2
Sleep 1s
Enter
Sleep 1s
Down
Sleep 1s
Enter
Sleep 1s
Type@200ms demonstration.com
Sleep 1s
Enter
Sleep 3s
Down@200ms 2
Sleep 1s
Enter

Sleep 5s

# Proceed with request
Down@200ms 5
Sleep 1s
Enter
Sleep 1s
Enter
Sleep 1s
# A published password!? :D
Type oCYsOa1NMUWhrU7EZHGHLHQ4i09hAO80JfONwzTV
Enter

Sleep 5s



# Uninstall root CA certificate operation
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
