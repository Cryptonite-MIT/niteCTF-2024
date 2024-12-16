# Challenge Setup Guide

## Commands to ensure VM communication

```bash
# Set interface to host only
interface GigabitEthernet1
ip address 192.168.204.2 255.255.255.0  # Example IP for host-only network
no shutdown
exit
```

## Enable HTTP Server

```bash
enable
configure terminal
ip http server
ip http secure-server
exit
```

## Disable Telnet and SSH Access

```bash
Router(config)# line vty 0 4
Router(config-line)# transport input none
Router(config-line)# exit
Router(config)# exit
Router# write memory
```

```bash
Router> enable
Router# configure terminal
Router(config)# no ip ssh
Router# write memory
```
<!-- 
## Create a local user with privilege 15

```bash
username admin privilege 15 secret YourPasswordHere
``` -->

## Set console password

```bash
Router(config)# line con 0
Router(config-line)# password <your_console_password>
Router(config-line)# login
Router(config-line)# exit

Router(config)# line aux 0
Router(config-line)# password <your_aux_password>
Router(config-line)# login
Router(config-line)# exit
```
<!-- 
## Set Privileged EXEC password

```bash
Router(config)# enable secret <your_enable_secret_password>
``` -->

## Passwords

user: `admin`
password: `pwn_m3_d4ddy`

console password: `n0t_@_fl4g_!0!`
