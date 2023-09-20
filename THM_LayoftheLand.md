## **TASK 4: AD ENVIRONMENT:** 
- For information abou tthe machine, includiung the O/S/version, hostname, and other hardware information as well as the AD Domain: 
  - ```systeminfo | findstr Domain```

## **TASK 5: USERS/GROUPS MANAGEMENT:**
#AD DIRECTORY ENUMERATION: 
- To get all active directory user accounts: 
  - ```Get-ADUser -Filter *```
- To specify a particular Distinguished Name collection (CN, DC, OU), use: 
  - ```get-aduser -filter * searchbase "ou=<>,cn=<>,dc=<>" ```

## **TASK 6: HOST SECURITY SOLUTIONS #1**
#For Antivirus running on the windows computer, use the following PS commands: 
  - ```wmic /namespace:\\root\securitycenter2 path antivirusproduct```
  - ```get-ciminstance -namespace root/securitycenter2 -classname antivirus product```
    - *Windows may not have "SecurityCenter2" namespace.  
     
***#Service State of Windows Defender:*** 
- ```get-service windefend```  
  
***#Security solutions elements:*** 
- ```get-mpcomputerstatus```
  
![windows security solution elements](https://github.com/ryangreggw/THM-BOXES/assets/25268281/74bc9c50-b627-460b-aade-590222037d5d)


***#WINDOWS DEFENDER STATUS:*** 
- ```get-mpcomputerstatus | select Realtimeprotectionenabled```

***#HOST BASED FIREWALL:***   

- ```get-netfirewallprofile | format-table name, enabled```
 
![windows netfirewall](https://github.com/ryangreggw/THM-BOXES/assets/25268281/eae1f0e1-27da-4f78-b2c0-99803d4374a2)


- If you have privileges, you can use the following command to turn them off: 
  - ```set-netfirewallprofile -profile domain, public, private -enabled false```

***#CHECKING FIREWALL RULES:***  

- ```get-netfirewallrule | select displayname, enabled, description``` 

![windows firewall rules](https://github.com/ryangreggw/THM-BOXES/assets/25268281/e85b138f-5957-450e-820e-f6de3e3ae664)


***#TESTING INBOUND CONNECTIONS (ASSUMING THERE IS A FIREWALL IN PLACE):*** 
- ```test-netconnection -computername 127.0.0.1 -port 80```

![windows test net connection command](https://github.com/ryangreggw/THM-BOXES/assets/25268281/4b30c92d-3080-42db-9928-f02d09c4b8bb)


***#THREAT DETAILS THAT HAVE BEEN DETECTED BY MS DEFENDER:*** 
- ```get-mpthreat```
  - Look under "Resources."

***#Enumerating firewall rules to find port that is allowed:***
- ```show-netfirewallrule```
- ```show-netfirewallrule | findstr THM-Connection```
- Usually powershell isn't case-sensitive but if you don't capitalize THM or Connection, it won't populate. 

![firewall enum](https://github.com/ryangreggw/THM-BOXES/assets/25268281/74a4d72b-5c8a-4671-8c5d-49945fa4bb0e)


## **TASK 7: HOST SECURITY SOLUTION #2**

#Event Logs: 
- `get-eventlog -list`

#DETECTING SYSMON - SYSINTERNAL SUITE THAT LOGS EVENTS
- Looking for sysmon through PS:
  - `get-process | where-object { $_.ProcessName -eq "Sysmon" }`
- Looking for services: 
  - `get-ciminstance win32_service -filter "Description = 'System Monitor service'"`

***#SYSINTERNAL SUITE ON WINDOWS COMPUTERS:*** 

![2023-09-19 09_48_19-SysinternalsSuite](https://github.com/ryangreggw/THM-BOXES/assets/25268281/da723e27-26c8-4f62-ada1-7e46031bc4a4)


***#CHECKING WINDOWS REGISTRY THROUGH PS:*** 
- `C:\Users\ryang\OneDrive\Documents\pentest+\windows registry ps command.jpg`

![windows registry ps command](https://github.com/ryangreggw/THM-BOXES/assets/25268281/f7040433-cb99-40c7-80ed-9e57520125b8)


## **TASK 9: APPLICATIONS AND SERVICES**

***#INSTALLED APPLICATIONS:***
- Use `wmic` command to list all installed applications/versions: 
  - ```wmic product get name,version```
- To find hidden directories/backup files: 
  - `get-childitem -Hidden -Path C:\Users\kkidd\Desktop`

***#INTERNAL SERVICES:*** 
- List running services with: 
  - ```net start```
- To find information for a particular service: 
  - `wmic service where "name like '<service name>'" get Name, PathName`
    - EG): `wmic service where "name like 'thm service'" get Name,PathName`
- For more information: 
  - `get-process -name thm-service`
- To see what ports it's listening on: 
  - `netstat -noa |findstr "LISTENING" |findstr "2580"`

**#QUESTION 2: Visit the localhost for the flag:** 
  - Open up internet explorer: `http://<your machineip>:<port #>`

![thm service flag](https://github.com/ryangreggw/THM-BOXES/assets/25268281/df48a94e-f074-4331-933d-e68095432eac)


***#DNS ZONE TRANSFER:*** 
1. Execute the nslookup tool: 
  - `nslookup.exe`
2. Provide the DNS server that we need to ask (target machine): 
   - `server 10.10.x.x`
3. Conduct DNS zone transfer on the domain: 
   - `ls -d thmredteam.com`
   - `ls -d` lists the files contained in the DNS zone file directory "thmredteam.com"
4. Record the flag: 

![zone transfer flag](https://github.com/ryangreggw/THM-BOXES/assets/25268281/369ceba4-b5ec-4792-bd51-90dd142f0b99)


