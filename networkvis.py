from scapy.all import *
from collections import Counter
import plotly
import plotly.offline
import plotly.graph_objs as go
from plotly.subplots import make_subplots

import os
from datetime import date

if not os.path.exists("images"):
    os.mkdir("images")

print("Sniffing...")
packets = sniff(count=100)
print("Done...")

wrpcap('foo.pcap',packets)

packets = rdpcap('foo.pcap')

srcIP=[]
dstIP=[]
for pkt in packets:
    if IP in pkt:
        try:
                srcIP.append(pkt[IP].src)
        except:
            pass
        try:
                dstIP.append(pkt[IP].dst)
        except:
            pass


srcCnt=Counter()
dstCnt=Counter()

for ip in srcIP:
    srcCnt[ip] += 1

for ip in dstIP:
    dstCnt[ip] += 1


srcXData=[]
srcYData=[]
for ip, count in srcCnt.most_common():
    srcXData.append(ip)
    srcYData.append(count)

dstXData=[]
dstYData=[]
for ip, count in dstCnt.most_common():
    dstXData.append(ip)
    dstYData.append(count)


fig = make_subplots(
    rows=2, cols=2,
    subplot_titles=("Number of Packets to Host", "Number of Packets from Host")
    )


fig.add_trace( go.Bar(x=srcXData, y=srcYData, name="Source"),
        row=1, col=1,
        )   

fig.add_trace(
        go.Bar(x=dstXData, y=dstYData, name="Destination"), 
        row=1, col=2,
        )

fig.update_layout(height=1300, width=1300, title_text="Network Visualization")
fig.show()

now = date.today()
fig.write_image("images/"+ str(now) + ".webp")

