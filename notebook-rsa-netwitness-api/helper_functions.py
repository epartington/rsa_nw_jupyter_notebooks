import json
#import tldextract
import pandas as pd
import numpy as np
from collections import Counter

from matplotlib import pyplot as plt
from matplotlib import cm as cm

import pylab
from mpl_toolkits.mplot3d import Axes3D

plt.rcParams["figure.figsize"] = [12,9]
ATOMIC_KEYS = set(['service', 'payload', 'size', 'ip.dst', 'ip.src', 'udp.dstport', 'udp.srcport', 
                   'tcp.dstport', 'tcp.srcport', 'direction', 'ip.proto'])

def query_to_df(results):
    meta = {}
    for r in results:
        try:
            for f in r['results']['fields']:
                if not f['group'] in meta:
                        meta[f['group']] = {}
                if f['type'] in ATOMIC_KEYS:
                     meta[f['group']][f['type']] = f['value']
                else:
                    if not f['type'] in meta[f['group']]:
                        meta[f['group']][f['type']] = list()
                    meta[f['group']][f['type']].append(f['value'])
                meta[f['group']]['sessionid'] = f['group']
        except Exception as e:
            #print (f)
            #print (e)
            pass
    return pd.read_json(json.dumps([v for v in meta.values()]))


def correlation_matrix(df):
    fig = plt.figure()
    ax1 = fig.add_subplot(111)
    cmap = cm.get_cmap('Greys', 30)
    cax = ax1.imshow(df, cmap=cmap)
    plt.yticks(np.arange(0.0, len(df.index), 1), df.index)
    plt.xticks(np.arange(0.0, len(df.columns), 1), df.columns, rotation='vertical')
    # Add colorbar, make sure to specify tick locations to match desired ticklabels
    fig.colorbar(cax)
    plt.show()


import base64
import requests
import numpy as np
import pandas as pd
from time import sleep
from itertools import chain
import io
from datetime import timedelta, date
from IPython.display import display, HTML
# stolen from https://github.com/iiSeymour/sparkline-nb/blob/master/sparkline-nb.ipynb with some changes to make it work

def sparkline(data, figsize=(4, 0.25), **kwags):
    """
    Returns a HTML image tag containing a base64 encoded sparkline style plot
    """
    data = list(data)
    
    fig, ax = plt.subplots(1, 1, figsize=figsize, **kwags)
    ax.plot(data)
    for k,v in ax.spines.items():
        v.set_visible(False)
    ax.set_xticks([])
    ax.set_yticks([])    

    plt.plot(len(data) - 1, data[len(data) - 1], 'r.')

    ax.fill_between(range(len(data)), data, len(data)*[min(data)], alpha=0.1)
    
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plt.close()
    #print ('<img src="data:image/png;base64,{}"/>'.format(base64.b64encode(buf.read()).decode("utf-8")))
    return '<img src="data:image/png;base64,{}"/>'.format(base64.b64encode(buf.read()).decode("utf-8"))


# Written by Scott Moore (NetWitness/RSA) in Aug 2012 against NextGen v9.8
# using Python 3.2.3
#
# The purpose of this program is to demonstrate how to interact with NextGen
# using the RESTful API.  I hereby release this code into the public domain so
# you may do whatever you want with it.  However, if you make useful changes
# to it, you would generate good karma by posting it back to the NetWitness
# community.  :)
#
# BTW, this is my first python program and I taught myself as I went along,
# so apologies in advance for what is probably poor python style.
# One thing I could never figure out is how to get the error text returned
# by NextGen when a 4xx HTTP error code is received.  The URLError exception
# doesn't seem to contain the actual payload response (see the submit func).
# If anyone solves that, please post the solution on the NetWitness community
# site.  https://community.emc.com/go/netwitness
#
# Thanks and I hope you find this useful.

import urllib, urllib.request, urllib.parse, sys
import json
import re


response_data = bytearray()

class StringParams:
    """A class that parses a string into NextGen parameters.
    Example:
    id1=1 id2=10000 query="select * where service=80"
    
    This class will generate a dict with 3 keys from the string above:
    {'query': 'select * where service=80', 'id2': '10000', 'id1': '1'}
    """
    params = {}  # dictionary from the result of calling parse

    def parse(self, str):
        self.params    = {}
        backslash      = False
        quotes         = False
        checkQuote     = True
        skipWhitespace = True
        hexChar        = False
        p              = 0
        hexValue       = ""
        param          = ["", ""]
        
        for c in range(len(str)):
            ch = str[c]
            
            if checkQuote:
                if ch == '"' and not backslash:
                    quotes         = True
                    checkQuote     = False
                    skipWhitespace = False
                    continue
            
            if skipWhitespace:
                if ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r':
                    continue
                skipWhitespace = False
                checkQuote     = False
            
            if ch == '"' and quotes and not backslash:
                quotes     = False
                checkQuote = True
            elif (ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r') and not backslash and not quotes:
                # store active parameters
                if len(param[0]) > 0:
                    self.params[param[0]] = param[1]
                
                # reset state
                p = 0
                param = ["", ""]
                checkQuote     = True
                skipWhitespace = True
            elif ch == "=" and backslash == False and quotes == False and p == 0:
                p = 1  # go to value parameter
                checkQuote = True
                skipWhitespace = False
            elif ch == '\\' and backslash == False:
                backslash = True
            elif backslash:
                if hexChar:
                    hexValue = hexValue + ch
                    if len(hexValue) > 1:
                        # time to decoder
                        hexChar = False
                        backslash = False
                        value = int(hexValue, 16)
                        param[p] = param[p] + chr(value)
                        hexValue = ""
                elif ch == 'n':
                    param[p] = param[p] + '\n'
                    backslash = False
                elif ch == 't':
                    param[p] = param[p] + '\t'
                    backslash = False
                elif ch == 'r':
                    param[p] = param[p] + '\r'
                    backslash = False
                elif ch == '0':
                    param[p] = param[p] + '\0'
                    backslash = False
                elif ch == 'x':
                    hexChar = True
                    hexValue = ""
                else:
                    param[p] = param[p] + ch
                    backslash = False
            else:
                param[p] = param[p] + ch
                backslash = False
        
        # store active parameters
        if len(param[0]) > 0:
            self.params[param[0]] = param[1]

        
def getSupportedMessages(*args):
    """This function takes the current value of pathname and asks the service for all messages on that node.
    It then parses the json response to get the list of those messages and fill the message combobox"""
    try:
        global message_combo
        # request help on the current node (in the pathname text entry)
        res = submit(url.get(), pathname.get(), "help", "op=messages force-content-type=application/json", username.get(), password.get())
        # convert json response to a string
        s = res.decode("utf-8")
        # load json string into json decoder for later parsing, d is a dict of the json
        d = json.loads(s)

        # make sure our dict has a params parameter
        if 'params' in d:
            l = []
            # create a list of supported messages
            for msg in d['params']:
                l.append(msg)
            # take the list and set the combobox dropdown with all the supported messages
            message_combo['values'] = l
            message_combo.set(l[0])
    except:
        print("getSupportedMessages error: ", sys.exc_info()[0])


def getMessageHelp(*args):
    """This function takes the current value of pathname and message and displays help for it on the screen."""
    try:
        # request help on the current node (in the pathname text entry)
        s = "m=" + message.get() + " force-content-type=text/plain"
        res = submit(url.get(), pathname.get(), "help", s, username.get(), password.get())
    except:
        print("Unexpected error: ", sys.exc_info()[0])
    

def submit(url, pathname, message, parameters, username, password, headers=None, bin_data=None, post=None):
    """Submits a RESTful request to a NextGen service and returns the response"""
    try:
        # maximum amount of text that will be displayed in the request/response text boxes
        max_length = 64 * 1024 * 1024
   
        sp = StringParams()
        sp.parse(parameters)

        urlParamChar = "?"

        urlPath = url
        urlPath = urlPath + pathname
        if len(message) > 0:
            urlPath = urlPath + urlParamChar + "msg="
            urlPath = urlPath + message
            urlParamChar = "&"

        auth_handler = urllib.request.HTTPBasicAuthHandler()
        auth_handler.add_password(realm="NetWitness", uri=urlPath, user=username, passwd=password)
        opener = urllib.request.build_opener(auth_handler)
        urllib.request.install_opener(opener)
        
        data = urllib.parse.urlencode(sp.params)
        
        if bin_data != None:
            req = urllib.request.Request(urlPath + urlParamChar + data, bin_data)
        elif post == "POST":
            data = data.encode("utf-8")
            req = urllib.request.Request(urlPath, data)
        else:
            req = urllib.request.Request(urlPath + urlParamChar + data)
        
        if headers != None:
            for name, value in headers.items():
                req.add_header(name, value)
        
        #for name, value in req.header_items():
        #    print (name + ": " + value + "\n")
       
        if req.data != None:
            #print (req.data[0:max_length])
            return json.loads(req.data[0:max_length])

        with  urllib.request.urlopen(req) as response:
            res_data = response.read()
        
        # Uncomment the lines below if you want to see the HTTP headers returned
        #for i in response.info():
        #    response_text.insert("end", i + ": " + response.info()[i])
        #    response_text.insert("end", "\n")
        #response_text.insert("end", "\n")
        
        res_string = str()
        try:
            # try to convert to utf-8, if it fails, then assume it's binary
            # and strip out non-ascii characters
            res_string = res_data[0:max_length].decode("utf-8")
        except:
            # strip out all non-ascii control chars, use a mutable bytearray
            # first, then convert to string at end.
            ascii_ba = bytearray()
            for c in res_data:
                if (c > 31 and c < 127) or c == 13 or c == 10 or c == 9:
                    ascii_ba.append(c)
                # prevent excessively large responses in our text widget
                if len(ascii_ba) > max_length:
                    break
            res_string = ascii_ba.decode("ascii")

        # return original bytearray response
        return json.loads(res_data)
    except urllib.request.URLError as e:
        #global response_text
        if hasattr(e, 'reason'):
            print (e.reason)
        elif hasattr(e, 'code'):
            print ("HTTP Error " + e.code)
    finally:
        pass


def submitForm(*args):
    headers = {}
    headers['Accept'] = accept.get()
    return submit(url.get(), pathname.get(), message.get(), parameters.get(),\
    username.get(), password.get(), headers)

def submitFile(*args):
    """This method shows a file dialog and submits the chosen file to NextGen.
    This is primarily used to import a pcap to decoder (/decoder/import) or upload
    parsers or feeds (/decoder/parsers/upload")."""
    
    filepath = filedialog.askopenfilename()

    if len(filepath) == 0:
        return

    # open and read contents of file - no checking is performed for large files
    # beware - could get out of memory errors!
    with open(filepath, 'rb') as f:
        bin_data = f.read()
    
    headers = {}
    headers['Accept'] = accept.get()
    headers['Content-Type'] = 'application/octet-stream'
    headers['X-pcap'] = filepath  # used to identify the filename for /decoder/import
    return submit(url.get(), pathname.get(), message.get(), parameters.get(),\
    username.get(), password.get(), headers, bin_data)

def savePayload(*args):
    """Saves the returned REST response to a file."""
    filepath = filedialog.asksaveasfilename()
    if len(filepath) == 0:
        return
    
    with open(filepath, 'wb') as f:
        f.write(response_data)


### easy 3d plotting
#ax = plt.figure().gca(projection='3d')
#ax.scatter(df['s'].tolist(), df['p'].tolist(), df['t'].tolist())
#ax.set_xlabel('Service')
#ax.set_ylabel('Payload')
#ax.set_zlabel('TCP DstPort')
#plt.show()
