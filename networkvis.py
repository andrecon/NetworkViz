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

# from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


def _showTopSrc(root, text):
    l1i = tk.Label(root,text =text)
    l1i.grid(row=3)

def _showTopDst(root, text):
    l2o = tk.Label(root, text = text)
    l2o.grid(row=5)


def _show(canvas, root):
     canvas.get_tk_widget().grid(row=8)

def _save(entry, fig, root):
     # fig.show()
     title = entry.get()
     fig.write_image("images/"+ title + ".pdf")
     # fig.write_image("images/fig1.webp")

def _sniff(stringInt, root):
    if not os.path.exists("images"):
        os.mkdir("images")

    print("Sniffing...")
    num = int(stringInt.get())
    packets = sniff(count=num)

    # packets = sniff(count=num)
    print("Done...")
    print(num)

    wrpcap('foo.pcap',packets)

    packets = rdpcap('foo.pcap')

    srcIP=[]
    dstIP=[]
    for pkt in packets:
     if IP in pkt:
            try:
                print(pkt[IP].src)
                srcdata = socket.gethostbyaddr(pkt[IP].src)
                tmp = socket.gethostbyaddr(pkt[IP].src)
                scrap = tmp[0].split(".")[0]
                info = (srcdata[0].strip(scrap)).strip('.')
                if not info:
                     srcIP.append(pkt[IP].src)
                else:
                     srcIP.append(info)
            except:
                print("Skipping Non-IPv4 packets")
                pass
            try:
                print(pkt[IP].dst)
                dstdata = socket.gethostbyaddr(pkt[IP].dst)
                tmp = socket.gethostbyaddr(pkt[IP].dst)
                scrap = tmp[0].split(".")[0]
                info = (dstdata[0].strip(scrap)).strip('.')
                if not info:
                     dstIP.append(pkt[IP].dst)
                else:
                     dstIP.append(info)
            except:
                print("Skipping Non-IPv4 packets")
                pass

    topSrc=Counter(srcIP).most_common(3)
    topDst=Counter(dstIP).most_common(3)
    
    if(len(topSrc) == 3):
         topSrcMessage= str(topSrc[0][0] + "\n"+ topSrc[1][0]+ "\n"+ topSrc[2][0])
    if(len(topDst) == 3):
         topDstMessage= str(topDst[0][0] + "\n"+ topDst[1][0]+ "\n"+ topDst[2][0])
    if(len(topSrc) == 2):
         topSrcMessage= str(topSrc[0][0] + "\n"+ topSrc[1][0])
    if(len(topDst) == 2):
         topDstMessage= str(topDst[0][0] + "\n"+ topDst[1][0])
    if(len(topSrc) == 1):
         topSrcMessage= str(topSrc[0][0])
    if(len(topDst) == 1):
         topDstMessage= str(topDst[0][0])
    if(len(topSrc) == 0):
         topSrcMessage= "No Incoming IP packets [might not be IPv4, Try Again]"
    if(len(topDst) == 0):
         topDstMessage= "No Outgoing IP packets [might not be IPv4, Try Again]"

    b5 = tk.Button(root,text = 'Top Incoming', command=(lambda e=root: _showTopSrc(e,topSrcMessage)))
    b5.grid(row=2)
    b6 = tk.Button(root,text = 'Top Outgoing', command=(lambda e=root: _showTopDst(e,topDstMessage)))
    b6.grid(row=4)

    srcCnt=Counter()
    dstCnt=Counter()

    sourceInt = 0
    destinationInt = 0
    for ip in srcIP:
        srcCnt[ip] += 1
        sourceInt +=1

    for ip in dstIP:
        dstCnt[ip] += 1
        destinationInt += 1


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

    sourceX = range(sourceInt)
    destinationX = range(destinationInt)


    fig = plt.Figure(figsize=(5,4), dpi = 100)
    ax = fig.add_subplot(211)
    #This will create the bar graph for poulation
    pop = ax.bar(srcXData, srcYData)
    ax.set_ylabel('Number of Packets')
    # ax.xticks(srcIP,srcIP)
    #ax.set_xticklabels(srcIP, fontdict=None, minor=False, rotation="vertical")
    ax.set_xticklabels([])

    #The below code will create the second plot.
    ax2 = fig.add_subplot(212)
    #This will create the bar graph for gdp i.e gdppercapita divided by population.
    gdp = ax2.bar(dstXData, dstYData)
    ax2.set_ylabel('Number of Packets')
    # ax2.xticks(dstIP, dstIP)
    #ax2.set_xticklabels(dstIP, fontdict=None, minor=False, rotation="vertical")
    ax2.set_xticklabels([])


    chart_type = FigureCanvasTkAgg(fig,root)


    b4 = tk.Button(root,text = 'Preview', command=(lambda e=chart_type: _show(e,root)))
    b4.grid(row=7)


    fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("Incomming", "Outgoing")
          )


    fig.add_trace( go.Bar(x=srcXData, y=srcYData, name="Source"),
            row=1, col=1,
         )   

    fig.add_trace(
            go.Bar(x=dstXData, y=dstYData, name="Destination"), 
            row=1, col=2,
        )

     # chart_type = FigureCanvasTkAgg(fig,root)
     # chart_type.get_tk_widget().pack()

    fig.update_layout(height=1300, width=1300, title_text="Network Visualization")

    saveEnt = tk.Entry(root)
    saveEnt.grid(row=6, column=0)
    b5 = tk.Button(root,text = 'Save Graph', command=(lambda e=saveEnt: _save(e,fig, root)))
    b5.grid(row=6, column=1)

     # fig.show()


     # now = time.strftime("%m%d-%H%M%S")
     # fig.write_image("images/"+ now + ".pdf")
     # fig.write_image("images/fig1.webp")

def exit(event):
    root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    root.title('NetworkViz')
    # root.configure(background='black')


    w = tk.Label(root, text="Num packets")
    w.grid(row=0)
   # x = (root.winfo_screenwidth() - root.winfo_reqwidth()) / 2
   # y = (root.winfo_screenheight() - root.winfo_reqheight()) / 2
    # root.geometry("500x500+%d+%d" % (x, y))
   # root.geometry("500x500+400+400")
    ent = tk.Entry(root)
    ent.grid(row=1, column=0)
    b1 = tk.Button(root,text = 'Sniff', command=(lambda e=ent: _sniff(e,root)))
    b1.grid(row=1, column=1)
#    root.bind('<Return>', (lambda e=ent: _sniff(e,root)))
    b3 = tk.Button(root, text='Quit', command=root.quit)
    b3.grid(row=100)
    root.bind('<Escape>', exit)


    root.mainloop()
