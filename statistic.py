# -*- coding: utf-8 -*-
"""
Created on Thu May 10 23:40:27 2018

@author: root
"""

import pandas as pd

csv = pd.read_csv("alert.csv")
pd.set_option('display.max_columns', 100)

#############################################
#总体分析
print(csv.describe(include = "all"))
#############################################

##########################################################################
#对时间戳的处理
for i in range(len(csv.timestamp)):
    csv.loc[i, ["timestamp"]] = csv.loc[i, ["timestamp"]].values[0][6:14]
csv.to_csv("alert.csv", index=False)
##########################################################################


###############################################################################################################
#时间段生成和分析
i = 0
total_time = int(1440)
step = int(30)
temp = pd.Series(index = range(int(total_time / step)))
timestamp_counts_freq = pd.Series(index = csv.timestamp.value_counts().index)
while i < total_time / step:
    for j in range(24):
        for k in range(0, 59, step):
            if j == 23 and k == 60 - step:
                temp[i] = ((str(j) + ':' + str(k) + ":00->" + "00:00:00"))
                i += 1
                continue
            if k == 60 - step:
                temp[i] = ((str(j) + ':' + str(k) + ":00->" + str(j + 1) + ':' + "00:00"))
                i += 1
                continue
            if k == 0:
                temp[i] = ((str(j) + ':' + "00:00->" + str(j) + ':' + str(k + step) + ":00"))
                i += 1
                continue
            temp[i] = ((str(j) + ':' + str(k) + ":00->" + str(j) + ':' + str(k + step) + ":00"))
            i += 1

timestamp_counts = pd.DataFrame(index = range(int(total_time / step)))
timestamp_counts.loc[:, "Period"] = temp
timestamp_counts.loc[:, "Times of alert"] = int(0)

for i in range(len(csv.timestamp.value_counts())):
    abc = csv.timestamp.value_counts().index[i].split(':')
    timestamp_counts.iloc[int(abc[0]) * 2 + int(int(abc[1]) / step), 1] += csv.timestamp.value_counts()[i]

timestamp_counts.plot(xticks=(1,5,9,13,17,21,25,29,33,37), grid=True, figsize=(16,9))



#下面两行代码用以生成xticks参数
for i in range(1, 40, 3):
    print(i, ',', end = "", sep = "")


###############################################################################################################


##################################################################################################
#攻击源IP分析
csv.src.value_counts()
csv.src.value_counts().iloc[0:50,].plot.pie(figsize = (10, 10), autopct = "%.1f", fontsize = 6)
##################################################################################################


###############################################################################################
#目标IP分析
csv.dst.value_counts()
csv.dst.value_counts().iloc[:50,].plot(figsize = (10, 10), fontsize = 8, kind = "bar")
###############################################################################################


########################################################################################################
#报警类型分析
df_msg = pd.DataFrame(index=range(len(csv.msg.value_counts())), columns=["No.","type","times"])
for i in range(len(csv.msg.value_counts())):
    df_msg.iloc[i,0] = i
    df_msg.iloc[i,1] = csv.msg.value_counts().index[i]
    df_msg.iloc[i,2] = csv.msg.value_counts()[i]
    
df_msg[["No.", "times"]] = df_msg[["No.", "times"]].apply(pd.to_numeric)

print(df_msg)
df_msg.plot(x = "No.", y = "times", kind = "scatter", color = 'r')
########################################################################################################


########################################################################################################################
#攻击源端口与目标端口分析
csv.srcport.value_counts()
csv.dstport.value_counts()
csv[["srcport", "dstport"]].plot(xticks = (-20000,-15000,-10000,-5000,0,5000,10000,15000,20000,25000,30000,35000,40000,45000,50000,55000,60000,65000,70000,75000,80000,85000,90000,95000), figsize = (10,5), fontsize = 6, kind = "kde")
########################################################################################################################
