#! /usr/bin/env python

from BaseHTTPServer import BaseHTTPRequestHandler,HTTPServer

import SocketServer
import SimpleHTTPServer
import CGIHTTPServer

import subprocess
import time
import shlex
import threading

#https://github.com/Pithikos/python-websocket-server
from websocket_server import WebsocketServer

PORT = 8000

#Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

#httpd = SocketServer.TCPServer(("", PORT), Handler)

#print "serving at port", PORT
#httpd.serve_forever()

class MyWebSocket():
    # Called for every client connecting (after handshake)
    def new_client(self,client, server):
        print("New client connected and was given id %d" % client['id'])
        cmd = "stdbuf -oL ./li_server -l 20000 -d"
        p = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
        while True:
            line = p.stdout.readline()
            if line != '':
                print line.rstrip()
                server.send_message(client,line)       
            else:
                break; 
        server.send_message(client,"End of the story")
        #server.send_message_to_all("Hey all, a new client has joined us")
    
    # Called for every client disconnecting
    def client_left(self,client, server):
        print("Client(%d) disconnected" % client['id'])
    
    
    # Called when a client sends a message
    def message_received(self,client, server, message):
        if len(message) > 200:
            message = message[:200]+'..'
            print("Client(%d) said: %s" % (client['id'], message))

    def run(self):
         t = threading.Thread(target = self.startup_ws_server)
         t.start()
        
    
    def startup_ws_server(self):
        WSPORT = 9001
        server = WebsocketServer(port = WSPORT, host = "0.0.0.0")
        server.set_fn_new_client(self.new_client)
        server.set_fn_client_left(self.client_left)
        server.set_fn_message_received(self.message_received)
        server.run_forever()    
 

class myHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    
    #Handler for the GET requests
    #OUTPUT = ""
    def do_GET(self):
        print "liam: ", self.path
        if self.path == "/start":
            self.send_response(200)
            self.send_header('Cache-Control','no-cache, no-store, must-revalidate')
            self.send_header('Content-type','text/html')
            self.end_headers()
            self.wfile.write("Starting...")
#            cmd = "stdbuf -oL ./li_server -l 20000"
#            p = subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
#            while True:
#                time.sleep(3)
#            while True:
#                line = p.stdout.readline()
#                print "line: ",line
#                if line != '':
#                    #print line.rstrip()
#                    global OUTPUT
#                    OUTPUT += line
#                else:
#                    break; 
        elif self.path == "/increment":
            self.send_response(200)
            self.send_header('Content-type','text/html')
            self.end_headers()
            # Send the html message
            #self.wfile.write(os.system("./li_server"))
            print OUTPUT
            self.wfile.write(OUTPUT)
           
        else:
            SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

try:
    ws = MyWebSocket()
    ws.run()
    #Create a web server and define the handler to manage the
    #incoming request
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer(('', PORT), myHandler)
    print 'Started httpserver on port ' , PORT
	
    #Wait forever for incoming htto requests
    server.serve_forever()

except KeyboardInterrupt:
    print '^C received, shutting down the web server'
    server.shutdown()
    
