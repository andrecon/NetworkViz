from scapy.all import *
from collections import Counter
import plotly

print("Sniffing...")
packets = sniff(count=100)
print("Done...")

wrpcap('foo.pcap',packets)

packets = rdpcap('foo.pcap')

print("Sources")
for packet in packets:
    try:
        print(packet[IP].src)
    except:
        pass

srcIP=[]
for pkt in packets:
    if IP in pkt:
        try:
                srcIP.append(pkt[IP].src)
        except:
            pass

cnt=Counter()

for ip in srcIP:
    cnt[ip] += 1

xData=[]
yData=[]
for ip, count in cnt.most_common():
    xData.append(ip)
    yData.append(count)

plotly.offline.plot({
   "data":[plotly.graph_objs.Bar(x=xData, y=yData)],
"layout":plotly.graph_objs.Layout(title="Source IP Occurrence",
xaxis=dict(title="SRC IP"),
       yaxis=dict(title="Count"))})
