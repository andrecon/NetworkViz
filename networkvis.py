from scapy.all import *
from collections import Counter
import plotly
import plotly.offline
import plotly.graph_objs as go
from plotly.subplots import make_subplots

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

# plotly.offline.plot(
#     {
#         "data":[plotly.graph_objs.Bar(x=xData, y=yData)], 
#         "layout":plotly.graph_objs.Layout(title="Source IP Occurrence",
#         xaxis=dict(title="SRC IP"),
#         yaxis=dict(title="Count"))
#     }
#     )

fig = make_subplots(
    rows=2, cols=2,
    subplot_titles=("Number of Packets for Source", "Number of Packets for Destination")
    )


fig.add_trace( go.Bar(x=xData, y=yData, name="Source"),
        row=1, col=1,
        )   

fig.add_trace(
        go.Bar(x=xData, y=yData, name="Destination"), 
        row=1, col=2,
        )

fig.update_layout(height=1300, width=1300, title_text="Network Visualization")
fig.show()

