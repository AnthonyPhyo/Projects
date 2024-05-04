#import scapy
from scapy.all import *
#define the network you wanna monitor
interface = 'wlan0'
#define where the findings will be saved to
probeReqs = []

#if there is a request for network pages, save as netName
#if the netName is not in probeReqs array, add to it
def sniffProves(p):
  if p.haslayer(Dot11ProbeReq):
    netName = p.getlayer(Dot11ProbeReq).info
    if netName not in probeReqs:
      probeReqs.append(netname)
      print('[+] Detected New Probe Request: ' + netName)
