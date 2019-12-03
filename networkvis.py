from scapy.all import *
from collections import Counter
import plotly
import plotly.offline
import plotly.graph_objs as go
from plotly.subplots import make_subplots
import tkinter as tk

import os
import time

# import dns.reversename

# n = dns.reversename.from_address("207.223.160.0")
# print(n)
import socket

def _sniff(num):
    if not os.path.exists("images"):
        os.mkdir("images")

    print("Sniffing...")
    packets = sniff(count=num)
    print("Done...")
    print(num)

    wrpcap('foo.pcap',packets)

    packets = rdpcap('foo.pcap')

    srcIP=[]
    dstIP=[]
    for pkt in packets:
     if IP in pkt:
            try:
                srcdata = socket.gethostbyaddr(pkt[IP].src)
                tmp = socket.gethostbyaddr(pkt[IP].src)
                scrap = tmp[0].split(".")[0]
                info = (srcdata[0].strip(scrap)).strip('.')
                # srcIP.append(pkt[IP].src)
                srcIP.append(info)
            except:
                 pass
            try:
                dstdata = socket.gethostbyaddr(pkt[IP].dst)
                tmp = socket.gethostbyaddr(pkt[IP].dst)
                scrap = tmp[0].split(".")[0]
                info = (dstdata[0].strip(scrap)).strip('.')
                # print(dstdata.strip(scrap))
                # dstIP.append(pkt[IP].dst)
                dstIP.append(info)
            except:
                pass

    topSrc=Counter(srcIP).most_common(3)
    topDst=Counter(dstIP).most_common(3)

    print(topSrc)
    print(topDst)

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


    now = time.strftime("%m%d-%H%M%S")
    fig.write_image("images/"+ now + ".pdf")
    fig.write_image("images/fig1.webp")


if __name__ == '__main__':
    root = tk.Tk()
    x = (root.winfo_screenwidth() - root.winfo_reqwidth()) / 2
    y = (root.winfo_screenheight() - root.winfo_reqheight()) / 2
    # root.geometry("500x500+%d+%d" % (x, y))
    root.geometry("500x500+400+400")
    root.title = ('NetworkViz')
    ent = tk.Entry(root)
    ent.pack()
    ent.insert(0, "100")
    num = ent.get()
    myInt = int(num)
    b1 = tk.Button(root,text = 'Button', command=(lambda e=myInt: _sniff(e)))
    b1.pack(padx=5, pady=5)
    root.mainloop()
