#!/usr/bin/python2.7

import sys
import socket
import threading
import json
from collections import OrderedDict
import binascii
import datetime
import time


def server_loop(local_host, local_port, remote_host, remote_port):
    # create the server object
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # lets see if we can stand up the server
    try:
        print "Daemon is launched, do not close this windows"
        server.bind((local_host, local_port))
    except:
        print "[!!] Failed to listen on %s:%d" % (local_host, local_port)
        print "[!!] Check for other listening sockets or correct permissions"
        sys.exit(0)

    # listen with 5 backlogged--queued--connections
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # print out the local connection information
        print"[+] Received incomming connections from %s:%d" % (addr[0], addr[1])

        # start a new thread to talk to the remote host
        proxy_thread = threading.Thread(target=proxy_handler,
                                        args=(client_socket, remote_host, remote_port))
        proxy_thread.daemon = False

        proxy_thread.start()


def receive_from(connection):
    buffer = ""

    # We set a 2 second time out depending on your
    # target this may need to be adjusted
    connection.settimeout(0)

    try:
        # keep reading into the buffer until there's no more data
        # or we time out
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass

    return buffer


# modify any requests destined for the remote host
def request_handler(socket_buffer, client_socket_id):
    global logon_data
    worker_found = False
    rig_name = ''
    rig_email = ''

    # Here is the good part

    # If it is an Auth packet
    if ('submitLogin' in socket_buffer) or ('eth_login' in socket_buffer):
        json_data = json.loads(socket_buffer, object_pairs_hook=OrderedDict)
        print('[+] Auth in progress with address: ' + json_data['params'][0])

        # capture full worker name (contains wallet(.)(/) worker/rig name
        requester_worker_name = json_data['params'][0]

        # try to find our worker/wallet in the request worker_name, if so its one of our rigs, log some info about it
        # if there is no match, it's probably the DevFee
        # when workers first connect to proxy all initial logins should be captured
        if wallet in json_data['params'][0]:
            worker_found = False

            # check if if not already stored
            for json_dict in logon_data['logons']:
                key_ip = json_dict['src_ip']
                if key_ip == client_socket_id[0]:
                    worker_found = True
                    break

            # If worker not found, store it
            if worker_found is False:
                # check the worker name & dissect
                if "." in requester_worker_name and uses_dot_workername:
                    # worker name has a dot separating rig name from wallet,
                    # there could also be a email with denoted by slash
                    dot_index = requester_worker_name.index('.')
                    # see if we have a slash... just in case
                    if "/" in requester_worker_name:
                        slash_index = requester_worker_name.index('/')
                        # get everything in between
                        rig_name = requester_worker_name[dot_index + 1:slash_index]
                        # capture email - unused but might as well
                        rig_email = requester_worker_name[slash_index + 1:]
                    else:
                        # if no slash, then everything after dot is the worker/rigname
                        rig_name = requester_worker_name[dot_index + 1:]
                elif "/" in requester_worker_name and uses_slash_workername:
                    # worker name has a slash separating rig name, or could be a email too (not for checked yet)
                    slash_index = requester_worker_name.index('/')
                    rig_name = requester_worker_name[slash_index + 1:]
                elif ("/" in requester_worker_name and not uses_slash_workername) or (
                                "." in requester_worker_name and not uses_dot_workername):
                    print('[!] Address might contain a worker/rig name but uses_dot_workername(' + str(
                        uses_dot_workername) + ') & uses_slash_workername(' + str(
                        uses_slash_workername) + ') ? ' + str(datetime.datetime.now()))
                    print('[!] :: ' + requester_worker_name)

                # capture
                logon_data['logons'].append({
                    'src_ip': client_socket_id[0],
                    'src_port': client_socket_id[1],
                    'rig_name': str(rig_name),
                    'rig_email': str(rig_email),
                    'requester_logon_name': str(requester_worker_name),
                })

                print ('[+] Stored worker name for client (' + str(client_socket_id[0]) + ':' + str(
                    client_socket_id[1]) + ') : ' + str(rig_name))
                print ('[+] Stored logons: ' + str(logon_data['logons']))
        else:
            # found_client_socket_id = ''
            for json_dict in logon_data['logons']:
                key_ip = json_dict['src_ip']
                key_rigname = json_dict['rig_name']
                rig_email = json_dict['rig_email']

                # print ("JSON DICT_: " + json.dumps(json_dict))
                # print("key: {0} | value: {1}".format(json_dict['src_ip'], json_dict['requester_logon_name']))

                # if the src_address matches a entry, then we found the worker name for that client
                # sub in worker name for the requesting client
                if key_ip == client_socket_id[0]:
                    # found_client_socket_id = key_ip
                    rig_name = key_rigname
                    # tack on email if found last round
                    if len(rig_email) != 0:
                        rig_name = rig_name + "/" + rig_email
                    worker_found = True
                    break

            if worker_found is True:
                print ('[+] Found previously used worker for client (' + str(client_socket_id[0])
                       + ':' + str(client_socket_id[1]) + ') : %s ' % rig_name)

            # Ident. the worker fee if we're told to do so, change the rig/worker name
            if identify_dev_fee is True:
                old_rig_name = rig_name
                rig_name = dev_fee_worker
                print ('[+] Identify DevFee is set :: Worker Change (' + old_rig_name + '==>' + rig_name + ')')

        # If the auth contain an other address than ours
        if wallet not in json_data['params'][0]:
            print('[*] DevFee Detected - Replacing Address - ' + str(datetime.datetime.now()))
            print('[*] OLD: ' + json_data['params'][0])
            # We replace the address, sub in the worker name for the connected client if found
            if len(rig_name) > 0 and uses_dot_workername:
                json_data['params'][0] = wallet + '.' + rig_name
            elif len(rig_name) > 0 and uses_slash_workername:
                json_data['params'][0] = wallet + '/' + rig_name
            else:
                # no worker_name so just replace the wallet
                json_data['params'][0] = wallet
            print('[*] NEW: ' + json_data['params'][0])

        socket_buffer = json.dumps(json_data) + '\n'

    # Packet is forged, ready to send.
    return socket_buffer


# modify any responses destined for the local host
def response_handler(buffer):
    return buffer


def proxy_handler(client_socket, remote_host, remote_port):
    # We prepare the connection
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)  # Enable keepalive packets

    # Get Client Address and Port
    client_socket_info = client_socket.getpeername()

    # We will try to connect to the remote pool
    for attempt_pool in range(3):
        try:
            remote_socket.connect((remote_host, remote_port))
        except:
            print "[!] Impossible to connect to the pool. Try again in few seconds "
            time.sleep(2)
        else:
            # Connection OK
            break
    else:
        print "[!] Impossible initiate connection to the pool. Claymore should reconnect. (Check your internet connection) " \
              + str(datetime.datetime.now())

        # Closing connection
        client_socket.shutdown(socket.SHUT_RDWR)
        client_socket.close()

        # Exiting Thread
        sys.exit()

    # now let's loop and reading from local, send to remote, send to local
    # rinse wash repeat
    while True:

        # read from local host
        local_buffer = receive_from(client_socket)

        if len(local_buffer):

            # send it to our request handler
            local_buffer = request_handler(local_buffer, client_socket_info)

            # print local_buffer

            # Try to send off the data to the remote pool
            try:
                remote_socket.send(local_buffer)
            except:
                print "[!] Sending packets to pool failed."
                time.sleep(0.02)
                print "[!] Connection with pool lost. Claymore should reconnect. (May be temporary) " \
                      + str(datetime.datetime.now())
                # Closing connection
                client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
                # Exiting loop
                break

            # Adding delay to avoid too much CPU Usage
            time.sleep(0.001)

        # receive back the response
        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):

            # send to our response handler
            remote_buffer = response_handler(remote_buffer)

            # print local_buffer

            # Try to send the response to the local socket
            try:
                client_socket.send(remote_buffer)
            except:
                print('[-] Auth Disconnected - Ending Devfee or stopping mining - ' + str(datetime.datetime.now()))
                client_socket.close()
                break

            # Adding delay to avoid too much CPU Usage
            time.sleep(0.001)
        time.sleep(0.001)

    # Clean exit if we break the loop
    sys.exit()


def main():
    # cursory check of command line args
    if len(sys.argv[1:]) != 5:
        print "Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport] [ETH Wallet]"
        print "Example: ./proxy.py 127.0.0.1 9000 eth.realpool.org 9000 0x..."
        sys.exit(0)

    # set up listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    # set up remote targets
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    # prime logon/worker name pool
    global logon_data
    logon_data = {}
    logon_data['logons'] = []

    # Set the wallet
    global wallet
    wallet = sys.argv[5]
    
    global worker_name
    worker_name = 'rekt'

    # Uncomment if you meet issue with pool or worker name - This will disable the worker name
    # worker_name = ''

    pool_slash = ['dwarfpool.com']
    pool_dot = ['nanopool.org', 'ethpool.org', 'ethermine.org', 'alpereum.ch']
    if worker_name:
        if any(s in remote_host for s in pool_slash):
            global uses_slash_workername
            uses_slash_workername = True
            worker_name = '/' + worker_name
            print remote_host + " uses wallet/worker format"
        elif any(d in remote_host for d in pool_dot):
            global uses_dot_workername
            uses_dot_workername = True
            worker_name = '.' + worker_name
            print remote_host + " uses wallet.worker format"
        else:
            # No worker name for compatbility reason
            print "Unknown pool - Worker name is empty"
            worker_name = ''

    print "Wallet set: " + wallet + worker_name

    # now spin up our listening socket
    server_loop(local_host, local_port, remote_host, remote_port)


# True or False
# Worker name uses dot '.' eg. wallet.rigname
uses_dot_workername = False
# Worker name uses slash '/' eg. wallet/rigname
uses_slash_workername = False
# Identify DevFee - Worker/Rig Name will be namne 'DevFee'
identify_dev_fee = True
dev_fee_worker = "DevFee"

if __name__ == "__main__":
    main()
