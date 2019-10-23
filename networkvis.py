from scapy.all import *
from collections import Counter
import plotly
# from prettytable import PrettyTable
# from scapy.all import wrpcap, Ether, IP, UDP

packets = sniff(count=100)

wrpcap('foo.pcap',packets)

packets = rdpcap('foo.pcap')
# if IP in packets:
#     print(packets[IP].src)

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

# table= PrettyTable(["IP", "Count"])

# for ip, count in cnt.most_common():
#    table.add_row([ip, count])

# print(table)

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