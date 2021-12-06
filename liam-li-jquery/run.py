#! /usr/bin/env python

import os
import subprocess

#os.system("./li_server")

#p = subprocess.Popen(["./li_server", "-l", "20000","-d","-T","10"],stdout=subprocess.PIPE)
p = subprocess.Popen(["stdbuf","-oL","./li_server", "-l", "20000","-d","-T","10"],stdout=subprocess.PIPE)
while True:
    line = p.stdout.readline()
    #line,_ = p.communicate()
    if line != '':
        print line.rstrip()
    else:
        break;
