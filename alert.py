#alert.py  
# -*- coding: utf-8 -*-  
""" 
Created on Sat May 5 02:17:45 2018 
 
@author: root 
"""

import os
import sys
import subprocess
import tkinter as tk
from tkinter import *
from tkinter import scrolledtext

print("=========================================================================================")
param = input("Enter the parameter to run snort\nexample:-c snort.conf -v -l etc/snort/log -A fast\nParameter = ")

p_snort = subprocess.Popen("snort " + param, shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)

p_tail = subprocess.Popen("tail -F alert", shell = True, stdout = subprocess.PIPE, stderr = subprocess.PIPE)

keywords = input("\nEnter the keywords which needs to be filtered,use \",\" to separate different keywords\n**Attention**:The keywords are case-insensitive.\nKeywords = ")
print("=========================================================================================")

subprocess.Popen("snort " + param, shell = True)

kw = keywords.split(',')
print("Press CTRL+C to terminate\n**Now scanning:" + keywords + '\n')
root = Tk()
root.title("Alert!")
w, h = root.maxsize()
root.geometry("{}x{}".format(w, h))
txt1 = scrolledtext.ScrolledText(root, width = w, height = h, wrap = tk.WORD)
txt1.pack()
a = 0

if os.path.exists("alert") is False:
    root.destroy()
    sys.exit(1)

try:
    while bytes.decode(p_snort.stderr.readline()).upper().find("ERROR") == -1:
        line = p_tail.stdout.readline()
        if line:
            line_str = bytes.decode(line)
            alert_kw = ""
            for i in range(0, len(kw)):
                if line_str.upper().find(kw[i].upper()) != -1:
                    if alert_kw != "":
                        alert_kw += ',' + kw[i]
                    else:
                        alert_kw += kw[i]
            if alert_kw != "":
                print(' ' + '='*(len(alert_kw) + 13))
                print('|   ' + alert_kw + " alert!   |")
                print(' ' + '='*(len(alert_kw) + 13))
                print(line_str)
                a += 1
                alert = alert_kw + " alert!: " + line_str
                txt1.insert('insert', str(a) + ' => ' + alert + '\n')
                txt1.update()
                txt1.see('end')

    root.destroy()
    sys.exit(1)

except KeyboardInterrupt:
    root.mainloop()
