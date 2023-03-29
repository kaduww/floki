#!/usr/bin/python3
'''
Floki is an Iptables Port Forward based RTP relay

Project started on 2021-11-04

Contributors: 
        Carlos Eduardo Wagner
            kaduww@gmail.com, carlos@sippulse.com
            https://github.com/kaduww
            https://www.linkedin.com/in/carlos-eduardo-wagner-96bbb433/

Dependencies: python-iptables, sdp-transform, bencodepy, configparser, pid, flask, waitress
'''

import iptc
import random
import sys
import json
import sdp_transform
import configparser
import time
import pid
import bencodepy
import socket
from _thread import *
from flask import Flask
from waitress import serve

# Default configuration settings
port_min=16384
port_max=32767
manager_ip='0.0.0.0'
manager_port=2223

# Pidfile
pidfile = {
    'pidname': 'floki.pid',
    'piddir': '/var/run/'
}

active_calls={}
used_ports={}
interfaces={}
processed_calls=0
start_epoch=time.time()

flask_app = Flask(__name__)

# Get a random port from the allowed range
def get_new_port(call_uuid):
    global used_ports
    if len(used_ports) < port_max - port_min:
        port=random.randint(port_min,port_max)
        while port in used_ports:
            port=random.randint(port_min,port_max)
        used_ports[port]=call_uuid
        return port
    else:
        return False

# Insert the stream rule on iptables saving the callid as key
def insert_ipt_rule(call_uuid, ua_ip, ua_port, local_port, in_addr, out_addr):
    ua_port=str(ua_port)
    local_port=str(local_port)
    try:
        prerouting_rule={'dst': out_addr+'/32', 'protocol': 'udp', 'udp': {'dport': local_port}, 'comment': {'comment': call_uuid}, 'target': {'DNAT': {'to-destination': ua_ip+':'+ua_port}}}
        iptc.easy.insert_rule('nat', 'PREROUTING', prerouting_rule)

        postrouting_rule={'dst': ua_ip+'/32', 'protocol': 'udp', 'udp': {'dport': ua_port}, 'comment': {'comment': call_uuid}, 'target': {'SNAT': {'to-source': in_addr}}}
        iptc.easy.insert_rule('nat', 'POSTROUTING', postrouting_rule)
        return True
    except:
        return False

# Remove the rules from iptables, using the callid as key
def remove_ipt_rule(call_uuid=None):
    # Removing POSTROUTING rules
    for rule_d in iptc.easy.dump_chain('nat', 'POSTROUTING'):
        if 'comment' in rule_d:
            if rule_d['comment']['comment']==call_uuid:
                chain = iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING")
                rule = iptc.easy.encode_iptc_rule(rule_d)
                chain.delete_rule(rule)

    # Removing PREROUTING rules
    for rule_d in iptc.easy.dump_chain('nat', 'PREROUTING'):
        if 'comment' in rule_d:
            if rule_d['comment']['comment']==call_uuid:
                chain = iptc.Chain(iptc.Table(iptc.Table.NAT), "PREROUTING")
                rule = iptc.easy.encode_iptc_rule(rule_d)
                chain.delete_rule(rule)

# Handles events for requests
def handle_request(command):
    global active_calls, interfaces, processed_calls
    call_uuid=command['call_uuid']
    in_iface=command['in_iface']
    out_iface=command['out_iface']
    ua_ip=command['ua_ip']
    natted=command['natted']
    sdp_dict=sdp_transform.parse(command['sdp'])

    # Initial requests
    if call_uuid not in active_calls:
        processed_calls+=1
        #local_port=get_new_port(call_uuid)
        #if not local_port:
        #    return {"Result": 0, "Cause": "no more Ports"}

        in_addr=interfaces[in_iface]
        out_addr=interfaces[out_iface]
        media_list=[]

        # Do not trust on the SDP conection info if the UA is natted
        if natted:
            dst_ip=ua_ip
        else:
            dst_ip=sdp_dict['connection']['ip']

        # Change the SDP connection IP
        sdp_dict['connection']['ip']=out_addr

        # Iterate on the SDP streams
        i=0
        local_used_ports=[]
        while i < len(sdp_dict['media']):
            ua_port=sdp_dict['media'][i]['port']
            local_port=get_new_port(call_uuid)
            local_used_ports.append(local_port)
            media_list.append({
                "ua_port": ua_port,
                "local_port": local_port
            })
            # Change the media port
            sdp_dict['media'][i]['port']=local_port
            i+=1

            if(not insert_ipt_rule(call_uuid, dst_ip, ua_port, local_port, in_addr, out_addr)):
                return {"Result": 0, "call_uuid": call_uuid, "Cause": "Failed to insert iptables rule"}

        net_info={
            "in_addr": in_addr,
            "out_addr": out_addr
        }
        if not call_uuid in active_calls:
            active_calls[call_uuid]={}
        active_calls[call_uuid]['net_info']=net_info
        call_info={
            "local_out_addr": out_addr,
            "media_list": media_list
        }
        active_calls[call_uuid][ua_ip]=call_info
        active_calls[call_uuid]['local_used_ports']=local_used_ports

    else:
        # Sequential requests
        # Change the SDP connection IP
        sdp_dict['connection']['ip']=active_calls[call_uuid][ua_ip]['local_out_addr']
        # Iterate on the SDP streams
        i=0
        while i < len(sdp_dict['media']):
            ua_port=sdp_dict['media'][i]['port']
            i+=1
            for media_list in active_calls[call_uuid][ua_ip]["media_list"]:
                if media_list['ua_port']==ua_port:
                    # Change the media port
                    sdp_dict['media'][i-1]['port']=media_list['local_port']

    modified_sdp=sdp_transform.write(sdp_dict)

    active_calls[call_uuid]['last_request_sdp_received']=command['sdp']
    active_calls[call_uuid]['last_request_sdp_modified']=modified_sdp
    
    return {"Result": 1, "call_uuid": call_uuid, "sdp": modified_sdp}

# Handles events for replies
def handle_reply(command):
    global active_calls
    call_uuid=command['call_uuid']
    ua_ip=command['ua_ip']
    natted=command['natted']
    sdp_dict=sdp_transform.parse(command['sdp'])
    
    if call_uuid not in active_calls:
        return {"Result": 0, "Cause": "no request command for the uuid"}
    else:
        # Initial replies
        if ua_ip not in active_calls[call_uuid]:
            #local_port=get_new_port(call_uuid)
            #if not local_port:
            #    return {"Result": 0, "Cause": "no more Ports"}

            out_addr=active_calls[call_uuid]['net_info']['in_addr']
            in_addr=active_calls[call_uuid]['net_info']['out_addr']

            # Do not trust on the SDP conection info if the UA is natted
            if natted:
                dst_ip=ua_ip
            else:
                dst_ip=sdp_dict['connection']['ip']

            # Change the SDP connection IP
            sdp_dict['connection']['ip']=out_addr

            # Iterate on the SDP streams
            local_used_ports=[]
            media_list=[]
            i=0
            while i < len(sdp_dict['media']):
                ua_port=sdp_dict['media'][i]['port']
                local_port=get_new_port(call_uuid)
                local_used_ports.append(local_port)

                media_list.append({
                    "ua_port": ua_port,
                    "local_port": local_port
                })
                # Change the media port
                sdp_dict['media'][i]['port']=local_port
                i+=1
                if(not insert_ipt_rule(call_uuid, dst_ip, ua_port, local_port, in_addr, out_addr)):
                    return {"Result": 0, "call_uuid": call_uuid, "Cause": "Failed to insert iptables rule"}

            call_info={
                "local_out_addr": out_addr,
                "media_list": media_list
            }

            active_calls[call_uuid][ua_ip]=call_info
            active_calls[call_uuid]["local_used_ports"]+=local_used_ports

        else:
            # Sequential replies
            # Change the SDP connection IP
            sdp_dict['connection']['ip']=active_calls[call_uuid][ua_ip]['local_out_addr']
            # Iterate on the SDP streams
            i=0
            while i < len(sdp_dict['media']):
                ua_port=sdp_dict['media'][i]['port']
                i+=1
                for media_list in active_calls[call_uuid][ua_ip]["media_list"]:
                    if media_list['ua_port']==ua_port:
                        # Change the media port
                        sdp_dict['media'][i-1]['port']=media_list['local_port']
    
    modified_sdp=sdp_transform.write(sdp_dict)

    active_calls[call_uuid]['last_reply_sdp_received']=command['sdp']
    active_calls[call_uuid]['last_reply_sdp_modified']=modified_sdp

    return {"Result": 1, "call_uuid": call_uuid, "sdp": modified_sdp}

# Handles the NG Protocol commands
def handle_rtpe_commands(request, UDPServerSocket, server_address):
    global used_ports, active_calls
    cookie=request.decode("utf-8").split(" ")[0]
    command=str.encode(request.decode("utf-8")[len(cookie)+1:]+"e")    
    command_decoded=bencodepy.decode(command)
    body={"call_uuid": None,
    "in_iface": None,
    "out_iface": None,
    "ua_ip": None,
    "natted": False,
    "sdp": None}

    reply={}
    if command_decoded[b"command"] == b"ping":
        reply["result"]="pong"

    if command_decoded[b"command"] == b"offer":
        body["call_uuid"]=command_decoded[b"call-id"].decode("utf-8")
        body["sdp"]=command_decoded[b"sdp"].decode("utf-8")
        if b"direction" in command_decoded:
            body["in_iface"]=command_decoded[b"direction"][0].decode("utf-8")
            body["out_iface"]=command_decoded[b"direction"][1].decode("utf-8")
        else:
            # if the direction is not set, use the first interface set for in and out
            body["in_iface"]=next(iter(interfaces))
            body["out_iface"]=body["in_iface"]
            #body["out_iface"]=next(iter(interfaces))

        body["ua_ip"]=command_decoded[b"received-from"][1].decode("utf-8")
        for flag in command_decoded[b"flags"]:
            if flag == b'SIP-source-address':
                body["natted"]=True
        response_body=handle_request(body)
        if "sdp" in response_body and response_body["Result"]==1:
            reply["sdp"]=response_body["sdp"]
            reply["result"]="ok"
        else:
            reply["result"]="error"
            reply["reason"]=response_body["Cause"]
            
    
    if command_decoded[b"command"] == b"answer":
        body["call_uuid"]=command_decoded[b"call-id"].decode("utf-8")
        body["sdp"]=command_decoded[b"sdp"].decode("utf-8")
        body["ua_ip"]=command_decoded[b"received-from"][1].decode("utf-8")
        for flag in command_decoded[b"flags"]:
            if flag == b'SIP-source-address':
                body["natted"]=True
        response_body=handle_reply(body)
        if "sdp" in response_body and response_body["Result"]==1:
            reply["sdp"]=response_body["sdp"]
            reply["result"]="ok"
        else:
            reply["result"]="error"
            reply["reason"]=response_body["Cause"]

    if command_decoded[b"command"] == b"delete":
        call_uuid=command_decoded[b"call-id"].decode("utf-8")
        if call_uuid in active_calls:
            for local_port in active_calls[call_uuid]["local_used_ports"]:
                del used_ports[local_port]
            del active_calls[call_uuid]
        remove_ipt_rule(call_uuid)
        reply["result"]="ok"

    reply_string=cookie+" "+ bencodepy.encode(reply).decode("utf-8")
    UDPServerSocket.sendto(str.encode(reply_string), server_address)

def start_flask():
    serve(flask_app, host=manager_ip, port=manager_port)

@flask_app.route('/list_calls', methods=['GET'])
def list_calls():
    return json.dumps(active_calls)

@flask_app.route('/status', methods=['GET'])
def status():
    return json.dumps({"start_epoch": int(start_epoch),
        "uptime_sec": int(time.time()-start_epoch),
        "processed_calls": processed_calls,
        "active_calls": len(active_calls),
        "rtp_port_range_size": port_max - port_min,
        "rtp_used_ports": len(used_ports),
        "rtp_available_ports": port_max - port_min - len(used_ports),
        "rtp_port_min": port_min,
        "rtp_port_max": port_max,
        "rtp_interfaces": interfaces})

config = configparser.ConfigParser()
try:
    if len(sys.argv) > 1:
        config.read(sys.argv[1])
    else:
        config.read('/etc/floki/floki.conf')
except:
    print("Failed to open the configuration file")
    sys.exit(1)

if not "general" in config:
    print("Missing general setting in the configuration file, using default general settings")
else:
    if "rtp_port_min" in config['general']:
        port_min=int(config['general']['rtp_port_min'])

    if "rtp_port_max" in config['general']:
        port_max=int(config['general']['rtp_port_max'])

    if "manager_ip" in config['general']:
        manager_ip=config['general']['manager_ip']

    if "manager_port" in config['general']:
        manager_port=int(config['general']['manager_port'])

    config.pop("general")

if len(config) == 0:
    print("No interface configuration found")
    sys.exit(1)

for interface in config:
    if "ip" in config[interface]:
        interfaces[interface]=config[interface]['ip']
    elif interface!="DEFAULT":
        print("IP configuration not set in interface %s, ignoring this one" % interface)

try:
    with pid.PidFile(**pidfile):
        start_new_thread(start_flask, ())
        UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        UDPServerSocket.bind((manager_ip, manager_port))
        while(True):
            bytesAddressPair = UDPServerSocket.recvfrom(4098)
            message = bytesAddressPair[0]
            server_address = bytesAddressPair[1]
            start_new_thread(handle_rtpe_commands, (message, UDPServerSocket, server_address))

except RuntimeError:
    print('Pidfile found')
    sys.exit(1)