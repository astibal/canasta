#!/usr/bin/env python
__disc__=\
"""
   Canasta - Collector log Analyzer by Ales Stibal
   Copyright: Ales Stibal, astibal@fortinet.com, Fortinet L2 TAC (c) 2013
   
   Disclaimer: Program has been written during the nights and exclusively in my spare time.  
               The program is dedicated to my beloved Kate and my awesome sons Vojtech and Filip.
               And also to all FSSO freaks working in Fortinet, of course!
   
   License: BSD original license
"""

__version__="0.1.4g"

import sys
import time
import datetime
import re
import logging
import argparse
import time
import os.path
import json
#import shlex

import cmd

from pprint import pprint
from pprint import pformat

import ipaddr

line_start=r'(?P<timestamp>\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d) +\[ *(?P<pid>\d+)\] +'
r_line_start = re.compile(line_start)

# ip check
func_update_entry_ip=r'(?P<function>update entry)\((?P<param>[\w ]+)\): +ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) +create time:(?P<create_time>\d+) +update time:(?P<update_time>\d+) +ip update time:(?P<ip_update_time>\d+) +workstation:(?P<wksta>[\w_.\-]+) +domain:(?P<domain>[\w_.-]+) +user:(?P<user>[\w_.-]+) +group:(?P<group>[\w_.,+=& \-]+)'
r_func_update_entry_ip = re.compile(line_start+func_update_entry_ip)
func_resolve_ip_internal=r'(?P<function>resolve_ip_internal): +workstation:(?P<fqdn>[\w.]+) +\[(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] +time:(?P<duration>\d+)'
r_func_resolve_ip_internal = re.compile(line_start+func_resolve_ip_internal)
func_after_dns_checking=r'after (?P<function>DNS_checking):(?P<wksta>[\w.]+)'
r_func_after_dns_checking = re.compile(line_start+func_after_dns_checking)
func_before_dns_checking=r'before (?P<function>DNS_checking):(?P<wksta>[\w.]+)'
r_func_before_dns_checking = re.compile(line_start+func_before_dns_checking)
func_dns_query_valid=r'(?P<function>DnsQuery)\(\): (?P<status>[^:]+): +ip:(?P<ip_hex>[\da-fA-F]+)'
r_func_dns_query_valid = re.compile(line_start+func_dns_query_valid)

# wksta_check
func_update_entry_workstation=r'(?P<function>update entry)\((?P<param>[\w ]+)\): +ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) +create time:(?P<create_time>\d+) +update time:(?P<update_time>\d+) +workstation:(?P<wksta>[\w_.\-]+) +domain:(?P<domain>[\w_.-]+) +user:(?P<user>[\w_.-]+) +group:(?P<group>[\w_.,+=& \-]+)'
r_func_update_entry_workstation = re.compile(line_start+func_update_entry_workstation)

func_wksta_verify_ip=r'verify_ip: workstation:(?P<wksta>[\w._-]+) \[(?P<ip1>[\d.]+):(?P<ip2>[\d.]+)\] time:(?P<time>\d+)'
r_func_wksta_verify_ip = re.compile(line_start+func_wksta_verify_ip)
func_wksta_test=r'user:(?P<user>\w+) on domain:(?P<domain>\w+) sid:(?P<sid>[\w-]+)'
r_func_wksta_test = re.compile(line_start+func_wksta_test)
func_wksta_registry_error=r'cannot access registry keys:(?P<err_code>\w+)'
r_func_wksta_registry_error = re.compile(line_start+func_wksta_registry_error)
#func_wksta_still=r'wksta_check: user:(?P<domain>[^\\]+)\\(?P<user>\w+) is still logged on to (?P<wksta>[\w-_.]+)'
func_wksta_still=r'wksta_check: user:(?P<domain>[^\\]+)\\(?P<user>\w+) is still logged on to (?P<wksta>[\w\-_.]+)'
r_func_wksta_still = re.compile(line_start+func_wksta_still)
#func_wksta_no_longer=r'wksta_check: user:(?P<domain>[^\\]+)\\(?P<user>\w+) is no longer logged on to (?P<wksta>[\w-_.]+) \((?P<ip1>[\d.]+)\)'
func_wksta_no_longer=r'wksta_check: user:(?P<domain>[^\\]+)\\(?P<user>\w+) is no longer logged on to (?P<wksta>[\w\-_.]+) \((?P<ip1>[\d.]+)\)'
r_func_wksta_no_longer = re.compile(line_start+func_wksta_no_longer)

# DC Agent processing workers
func_process_dcagent_events=r'process_dcagent_events called by worker:(?P<caller_pid>[\d]+)'
r_func_process_dcagent_events = re.compile(line_start+func_process_dcagent_events)
func_dcadgent_remove_q='dcagent packet: removed from queue, called:(?P<called>\d+) remain:(?P<remain>\d+)'
r_func_dcadgent_remove_q = re.compile(line_start+func_dcadgent_remove_q)

func_ntlm_begin='process_NTLM_requests called by worker:\d+'
r_func_ntlm_begin = re.compile(line_start+func_ntlm_begin)
#                       NTLM packet: removed from queue, called:31770355 remain:0
func_ntlm_remove_q='NTLM packet: removed from queue, called:(?P<called>\d+) remain:(?P<remain>\d+)'
r_func_ntlm_remove_q = re.compile(line_start+func_ntlm_remove_q)
func_logon_event=r'logon event\((?P<called>\d+)\): len:(?P<length>\d+) dc_ip:(?P<dc_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) time:(?P<dc_timestamp>\d+) len:\d+ data:(?P<wksta>[\w\d.-_]+)/(?P<domain>\w+)/(?P<user>[^\\ ]+) ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
r_func_logon_event = re.compile(line_start+func_logon_event)
func_logon_event_ex=r'logon event\((?P<called>\d+)\): len:(?P<length>\d+) dc_ip:(?P<dc_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) time:(?P<dc_timestamp>\d+) len:\d+ data:(?P<wksta>[\w\d.-_]+)/(?P<domain>\w+)/(?P<user>[^\\ ]+) ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
r_func_logon_event_ex = re.compile(line_start+func_logon_event_ex)
func_new_logon_0=r'(?P<function>new logon), +workstation:(?P<wksta>[^\ ]+)( \(cached:[^ ]+\))? +ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
r_func_new_logon_0 = re.compile(line_start+func_new_logon_0)
func_new_logon_1=r'(?P<function>new logon), +workstation:(?P<wksta>[^ ]+)( \(cached:[^ ]+\))? +ip not changed +(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
r_func_new_logon_1 = re.compile(line_start+func_new_logon_1)
func_ntlm_user=r'user:(?P<user>[^\\]+)'
r_func_ntlm_user = re.compile(line_start+func_ntlm_user)
func_ntlm_domain=r'domain:(?P<domain>[^\\]+)'
r_func_ntlm_domain = re.compile(line_start+func_ntlm_domain)
func_ntlm_wksta=r'workstation:(?P<wksta>[^\\]+)'
r_func_ntlm_wksta = re.compile(line_start+func_ntlm_wksta)
func_ntlm_seq=r'packet seq:(?P<ntlm_seq>\d+)'
r_func_ntlm_seq = re.compile(line_start+func_ntlm_seq)

func_cannot_resolve=r'cannot resolve workstation name:(?P<wksta>.*)'
r_func_dns_cannot_resolve = re.compile(line_start+func_cannot_resolve)

#DNS lookup: workstation name:NB-1110.schuledavos.net, dns server:(null), ip:00000000:00000000
func_dns_query=r'DNS lookup: workstation name:(?P<wksta>[^,]+), dns server:\([^\)]+\), ip:[\w\d]+:[\w\d]+'
r_func_dns_query = re.compile(line_start+func_dns_query)
# Fortigate receive IO workers (FIXME)
func_fortigate_io_recv=r'Bytes received from FortiGate: (?P<bytes>\d+)'
r_func_fortigate_io_recv = re.compile(line_start+func_fortigate_io_recv)
func_fortigate_io_ntlm_req=r'NTLM packet: add to queue, called:(?P<called>\d+), current:\d+'
r_func_fortigate_io_ntlm_req = re.compile(line_start+func_fortigate_io_ntlm_req)

# Fortigate send IO workers (FIXME)
func_fortigate_io_send=r'get record from send queue: sock:(?P<fdr>[\da-fA-F]+):(?P<fdw>[\da-fA-F]+) buffer:(?P<ptr>[\da-fA-F]+) len:(?P<data_length>\d+) queue size:(?P<queue_length>\d+)'
r_func_fortigate_io_send = re.compile(line_start+func_fortigate_io_send)

func_fortigate_io_failed=r'server send thread for socket:(?P<socket>[\da-f]+) exit. FGT close connection'
r_func_fortigate_io_failed = re.compile(line_start+func_fortigate_io_failed)
# Fortigate messaging worker (FIXME)
func_fortigate_msg_fgt_connected=r'(?P<count>[\d]+) FortiGates{0,1} connected'
r_func_fortigate_msg_fgt_connected = re.compile(line_start+func_fortigate_msg_fgt_connected)
func_fortigate_msg_cache_logon_send=r'check the cache to send logon events'
r_func_fortigate_msg_cache_logon_send = re.compile(line_start+func_fortigate_msg_cache_logon_send)
func_fortigate_msg_cache_logon_user=r'not in filter: last user:(?P<user1>[^ ]+) user:(?P<user2>[^ ]+)'
r_func_fortigate_msg_cache_logon_user = re.compile(line_start+func_fortigate_msg_cache_logon_user)
# group list unreliable, truncated at 900th character
func_fortigate_msg_cache_logon_group=r'not in filter: last user:(?P<group1>[^ ]+) user:(?P<group2>[^ ]+)'
r_func_fortigate_msg_cache_logon_group = re.compile(line_start+func_fortigate_msg_cache_logon_group)

func_fortigate_msg_cache_logoff_purge=r'check the cache to purge logoff entries'
r_func_fortigate_msg_cache_logoff_purge = re.compile(line_start+func_fortigate_msg_cache_logoff_purge)

# not matching '.' in username
# func_fortigate_msg_cache_logoff_user=r'(?P<wksta>[\w._-]+):(?P<user>\w+)\[(?P<ip1>[\d.]+):(?P<ip2>[\d.]+)\] removed. current time:(?P<current_time>\d+) last update time:(?P<update_time>\d+) age:(?P<age>\d+)'
func_fortigate_msg_cache_logoff_user=r'(?P<wksta>[\w._-]+):(?P<user>[^\\]+)\[(?P<ip1>[\d.]+):(?P<ip2>[\d.]+)\] removed. current time:(?P<current_time>\d+) last update time:(?P<update_time>\d+) age:(?P<age>\d+)'
r_func_fortigate_msg_cache_logoff_user = re.compile(line_start+func_fortigate_msg_cache_logoff_user)

func_fortigate_msg_cache_user_saved=r'logon cache saved to file'
r_func_fortigate_msg_cache_user_saved = re.compile(line_start+func_fortigate_msg_cache_user_saved)
func_fortigate_msg_cache_group_saved=r'group cache \(\d+\) saved to file'
r_func_fortigate_msg_cache_group_saved = re.compile(line_start+func_fortigate_msg_cache_group_saved)


# DC Agent messaging worker
func_dcagent_msg_received=r'Bytes received from DC agent\((?P<called>\d+)\): (?P<msg_bytes>\d+) dcagent IP: (?P<ip_hex>[\da-fA-F]+), MT=(?P<mt>\d+)'
r_func_dcagent_msg_received = re.compile(line_start+func_dcagent_msg_received)

# Group checking, while updating IP (done by different thread)
func_update_groupcheck=r'check the entry to see if the user\'s group info changed' # yes, no info inside!
r_func_update_groupcheck = re.compile(line_start+func_update_groupcheck)

# Main thread which is accepting TCP sessions from Fortigates
func_fortigate_io_accepted=r'accepting one FortiGate connection'
r_func_fortigate_io_accepted = re.compile(line_start+func_fortigate_io_accepted)

# Connection to FGT closed. return code:-1 last error:10053
func_fortigate_io_closed=r'Connection to FGT closed. return code:(?P<return>[\d-]+) last error:(?P<errno>[\d-]+)'
r_func_fortigate_io_closed = re.compile(line_start+func_fortigate_io_closed)
# send hello
func_fortigate_io_hello=r'send hello'
r_func_fortigate_io_hello=re.compile(line_start+func_fortigate_io_hello)

# server_send thread for sock:3696
func_fortigate_io_send_sock=r'server_send thread for sock:(?P<socket>[\d\a-f]+)'
r_func_fortigate_io_send_sock=re.compile(line_start+func_fortigate_io_send_sock)
# poller thread (FIXME)
# ... this time it's being ignored
# func_poller_debug_dcpoller=r'\[D\]\[DCPoller\].*'
# func_poller_arrows=r'\[I\]\[[LD][SC]Poller\][^>]+>$'

#[I][LSPoller]DoPolling(ip=2900510A, host=PC_D01/d3s011.lpti.le.grp): r=42
func_poller_dopoll_end=r'\[I\]\[LSPoller\]DoPolling\(ip=(?P<ip>[\d\w]+), host=(?P<fqdn>[\w\d./]+)\): r=(?P<r>\d+)'
r_func_poller_dopoll_end = re.compile(line_start+func_poller_dopoll_end)

#[I][LSPoller]DoPolling(ip=2900510A, host=PC_D01/d3s011.lpti.le.grp)-->
func_poller_dopoll_begin=r'\[I\]\[LSPoller\]DoPolling\(ip=(?P<ip>[\d\w]+), host=(?P<fqdn>[\w\d./]+)\)-->'
r_func_poller_dopoll_begin = re.compile(line_start+func_poller_dopoll_begin)

#[I][DCPoller]NSEnum(d5s08.lpp.le.grp): r=0, e=997, R=148, T=148, H=0x00095E46
func_poller_nsenum=r'\[I\]\[DCPoller\]NSEnum\(([\w\d.]+)\): r=\d+, e=\d+, R=\d+, T=\d+, H=0x[\da-fA-F]+'
r_func_poller_nsenum = re.compile(line_start+func_poller_nsenum)

#[D][DCPoller]SESI10: w=10.81.8.123, u=TPT567
func_poller_entry=r'\[D]\[DCPoller\]([\w\d]+): w=(?P<wksta>[\d\w.]+), u=(?P<user>[\w\d]+)'
r_func_poller_entry = re.compile(line_start+func_poller_entry)

#[I][LSPoller]PackMsg(w=10.81.8.124, u=TPT845, d=PC_D01, ip=2800510A, time=1357794964)
func_poller_login=r'\[I]\[LSPoller\]PackMsg\(w=(?P<wksta>[\d\w.]+), u=(?P<user>[\w\d]+), d=(?P<domain>[\d\w.]+), ip=(?P<dc_ip>[\dA-F.]+), time=(?P<tstamp>[\d]+)\)'
r_func_poller_login = re.compile(line_start+func_poller_login)


func_hb_send=r'send heart beat, sock:(?P<socket>[\da-f]+) len:\d+ SN:(?P<fgtsn>[\w\d]+)'
r_func_hb_send = re.compile(line_start+func_hb_send)

func_hb_0Fortigate=r'0 FortiGate connected'
r_func_hb_0Fortigate = re.compile(line_start+func_hb_0Fortigate)

"""
 GLOBAL LOGGING SETUP
"""
logger_state = logging.getLogger("state")
logger_analyzer = logging.getLogger("analyzer")
logger_plain = logging.getLogger("plain")

ch = logging.StreamHandler()
formatter = logging.Formatter('[%(levelname)s][%(name)s] %(message)s')
ch.setFormatter(formatter)

chh = logging.StreamHandler()
formatter_chh = logging.Formatter('%(message)s')
chh.setFormatter(formatter_chh)

logger_state.addHandler(ch)
logger_state.setLevel(logging.DEBUG)
logger_analyzer.addHandler(ch)
logger_analyzer.setLevel(logging.DEBUG)

logger_plain.addHandler(chh)
logger_plain.setLevel(logging.INFO)
    
"""
 Worker: class representing single worker thread on Collector agent. 
 Each log line is analyzed and the state of the worker is updated accordingly.
"""
class Worker:

    ROLE_UNKNOWN="unknown"
    ROLE_IGNORED="ignored"
    
    ROLE_UPDATERIP="updater-ip"
    ROLE_UPDATERWKS="updater-workstation"
    ROLE_LOGONS="logons-msg"
    
    ROLE_FGTIOMUX="fortigate-io-mux"
    ROLE_FGTIORECV="fortigate-io-recv"
    ROLE_FGTIOSEND="fortigate-io-send"
    ROLE_FGTMSG='fortigate-msg'
    ROLE_DCAGENTIORECV='dcagent-io-recv'
    ROLE_UPDATERGROUP='updater-groupcheck'
    ROLE_DOPOLL='poller'

    ROLE_FGTHB='fortigate-hbeat'

    def __init__(self,pid,workerset):
        self.pid = pid
        self.sub_pid = 0
        self.log = []
        self.poller_log = []
        
        self.roles = []
        self.roles_counter = {}
        self.parent = workerset
        
        # index of first state log entry
        self.state_index_a = 0
        # role of current state (may change, or doesn't have to -- no proves)
        self.state_role = Worker.ROLE_UNKNOWN
        # structure containing all state-specific data (updater data, logons data, ...)
        self.state_data = None
        # list of lines, per single state [[state_1_lines],[state_2_lines]]
        self.task_list = []

        # create sub-worker for event poller:
        #   event poller events are not parseable in this worker state, e.p. logs
        #   follow their own state, thus creating poller sub-worker
        
        if workerset.pid == 0:
            self.child_poller = Worker(pid,self)
            self.child_poller.sub_pid = 1
        else:
            self.child_poller = None
                
        
        # map of regular expressions idicating new cycle/state to roles
        self.new_state_events = {}
        # replace with removal event from queue -- this relpaced log line will be ignored, since we need  to hit all logon events, not just 
        # the first when the logons are removed from queue by more than one
        # ... and func_process_dcagent_events does not have much informational value anyway
        
        #self.new_state_events[line_start+func_process_dcagent_events] = Worker.ROLE_LOGONS
        self.new_state_events[r_func_dcadgent_remove_q] = Worker.ROLE_LOGONS
        self.new_state_events[r_func_ntlm_remove_q] = Worker.ROLE_LOGONS
        self.new_state_events[r_func_update_entry_ip] = Worker.ROLE_UPDATERIP
        self.new_state_events[r_func_update_entry_workstation] = Worker.ROLE_UPDATERWKS
        
        self.new_state_events[r_func_fortigate_io_recv] = Worker.ROLE_FGTIORECV
        self.new_state_events[r_func_fortigate_io_send] = Worker.ROLE_FGTIOSEND
        self.new_state_events[r_func_fortigate_io_failed] = Worker.ROLE_FGTIOSEND
        self.new_state_events[r_func_fortigate_io_hello] = Worker.ROLE_FGTIORECV
        self.new_state_events[r_func_fortigate_io_closed] = Worker.ROLE_FGTIORECV
        self.new_state_events[r_func_fortigate_io_send_sock] = Worker.ROLE_FGTIOSEND
        
        # removed on 0.1.1a -- seems to be right decision
        #self.new_state_events[r_+func_fortigate_msg_fgt_connected] = Worker.ROLE_FGTMSG
        self.new_state_events[r_func_fortigate_msg_cache_logon_send] = Worker.ROLE_FGTMSG
        self.new_state_events[r_func_fortigate_msg_cache_logoff_purge] = Worker.ROLE_FGTMSG
        self.new_state_events[r_func_fortigate_msg_cache_user_saved] = Worker.ROLE_FGTMSG
        self.new_state_events[r_func_fortigate_msg_cache_group_saved] = Worker.ROLE_FGTMSG
        
        self.new_state_events[r_func_dcagent_msg_received] = Worker.ROLE_DCAGENTIORECV
        self.new_state_events[r_func_update_groupcheck] = Worker.ROLE_UPDATERGROUP
        self.new_state_events[r_func_fortigate_io_accepted] = Worker.ROLE_FGTIOMUX
        self.new_state_events[r_func_poller_dopoll_begin] = Worker.ROLE_DOPOLL

        # ignored lines, which are duplicating info, or just unecessarily screw up parsing :)
        #self.new_state_events[line_start+func_poller_debug_dcpoller] = Worker.ROLE_IGNORED
        
        # let's ignore calling worker line. It may be a start of several worker tasks
        self.new_state_events[r_func_process_dcagent_events] = Worker.ROLE_IGNORED
        self.new_state_events[r_func_ntlm_begin] = Worker.ROLE_IGNORED
        
        self.new_state_events[r_func_hb_send] = Worker.ROLE_FGTHB
        self.new_state_events[r_func_hb_0Fortigate] = Worker.ROLE_FGTHB
        
        
    def data(self):
        return [ "Worker", { "pid": self.pid }, { "roles" : self.roles }, { "roles_counter": self.roles_counter }, { "task_list" : self.task_list } ]
        
    def _state_reset(self):
        self.state_index_a = len(self.log)-1
        self.state_role = Worker.ROLE_UNKNOWN
        self.state_data = None
    
    """
    line: generator of log lines
    """
    def lines(self):
        for l in self.log:
            yield l
    
    def tasks(self):
        for t in self.task_list:
            yield t

    def _role_start(self,role):
        if role not in self.roles:
            self.roles.append(role)
            self.roles_counter[role]=1
        else:
            self.roles_counter[role]+=1
        
        self.state_role = role

    def update_poller(self,line):
        if self.child_poller != None:
            self.child_poller.update(line)
            #print "poller: ",self.pid,line
              
    
    """
    update: let update worker with line from the log. 
    @return: None if no task is completed or task_data if the task is finished with this line
    """     
    def update(self, line):
        
        # check if we have poller sub-worker, otherwise continue
        if re.search('\[[DL][CS]Poller\]',line) and self.child_poller:
            self.update_poller(line)
            return None
     
        m = None
        m_r = Worker.ROLE_UNKNOWN
        
        for n in self.new_state_events:
            #m = re.match(n,line) 
            m = n.match(line) 
            if m:
                # set match role according new_state_event dictionary
                m_r = self.new_state_events[n]
                
                logger_state.debug("Worker "+ self.pid + ": new state: " + m_r + " : " + line)
                if m_r == Worker.ROLE_IGNORED:
                    logger_state.debug('Ignoring: %s' % (line,))
                    return None
                break

        # was originally before the for loop. But we don't want to include IGNORED lines
        # in the task list
        
        line_to_append = line.strip()
        
        # remove truncated, unfinished unicode character
        if line_to_append[-1] in ['\xc2', '\xc3' ]:
            logger_state.debug("%d: removed unfinished utf-8 prefix" % (len(self.log),))
            line_to_append = line_to_append[0:-1]
            
        self.log.append(line_to_append)
        
        current_index = len(self.log)-1
        #logger_state.debug(" ... current index:" + str(current_index))            
            
        if m:
            # log state stop and let finish it
            if len(self.log) > 1: 
                logger_state.debug("... STOP at index=%d, last line: " % (current_index -1,) + self.log[-2])
                logger_state.debug("... START at index=%d, last line: " % (current_index,) + self.log[-1])
                self.handle_finish()
            
            # restart state and set proper role (already matched)
            self._state_reset()
            self._role_start(m_r)
           
        # INSIDE STATE       
        logger_state.debug("... index=%d, start_index=%d, role=%s" % (len(self.log)-1, self.state_index_a, self.state_role))
                
        # this means we have just started the new task: return previous one
        if m and len(self.log) > 1:
            return self.task_list[-1]
            
        return None

    
    """
    handle_finish: complete the task, fill structures
    """
    def handle_finish(self):
        task_data = {}
        task_data['pid'] = self.pid
        task_data['sub_pid'] = self.sub_pid
        task_data['role'] = self.state_role
        task_data['data'] = self.state_data
        task_data['id'] = len(self.task_list)      
        task_data['gid'] = "%s-%s-%s" % (task_data['pid'],task_data['sub_pid'],task_data['id'])
        task_data['log'] = []
        for li in range(self.state_index_a,len(self.log)-1):
            logger_state.debug("+++ " + self.log[li])
            task_data['log'].append(self.log[li])
        
        self.task_list.append(task_data)

        self.finish_task(task_data)
            
        logger_state.debug("+++ ... task completed: id=%d, lines=%d, line index=(%d,%d)" % 
                (task_data['id'],len(task_data['log']),self.state_index_a,len(self.log)-1))


    def finish_task(self, task_data):
        if self.parent != None:
            self.parent.finish_task(task_data)
    

class Workers:
    """
     Workers: log entry dispatcher
     each log line is analyzed and according to pre-matched PID is distributed to it's corresponding
     worker object.
    """
    
    def __init__(self,ca_log):
    
        # for worker: if parent.pid == 0, then it's topmost worker
        self.pid = 0
        self.ca_log = ca_log
        self._workers = {}
        self.analyzer = Analyzer(self)
        
        # chrono list of tasks finished by workers
        self.task_chain = []
        # pid-id dict of tasks
        self.task_db = {}
        self.task_db_list = []
    
        self.chsearch_suffix = None
        self.output_stdout = False
    
    def data(self):
        r_sup = ["WORKERS", { "task_chain": self.task_chain }, { "task_db_list":self.task_db_list }, { "task_db":self.task_db } ] 
        r_chi = []
        for w in self.workers():
            r_chi.append(w.data())
            
        return [r_sup, r_chi]
    

    def finish_task(self,task_data):
        """
        add to the db task, as it came from the particular worker. The benefit to have
        another list/set of task_data is that we know their sequential order.
        The current mechanism to store "general" list of task is done using 
        chrono. list of task_id (attr task_db_list) and dictionary keyed by task_id (attr task_db)
        
        FIXME: new implementation should use sqlite
        """        
        # fill the data for the current task, since we hit the beginning the new one
        t_id_this = "%s-%s-%s" % (task_data['pid'],task_data['sub_pid'],task_data['id'])
        self.task_db[t_id_this] = task_data
        
        
        # because we finish the task when the new one is recognized
        #t_id_next = "%s-%s" % (task_data['pid'],task_data['id']+1)
        t_id_next = "%s-%s-%s" % (task_data['pid'],task_data['sub_pid'],task_data['id']+1)
        self.task_db_list.append(t_id_next)
        
    def analyze(self):
        count = 0
        delta = time.time()
        
        logger_analyzer.info("Going to analyze %d task references:" % (len(self.task_db_list),))
        
        for gid in self.task_db_list:
            count += 1
            
            if gid in self.task_db:
                logger_analyzer.debug("==> analyzing GID %s" % (gid,))
                task_data = self.task_db[gid]
                self.analyzer.analyze_task(task_data)
            else:
                logger_analyzer.debug("... analyzing GID %s: not found in the database" % (gid,))
        
            # time profiling
            if time.time() - delta > 10:
                delta = time.time()
                logger_analyzer.info("%d tasks processed ..." % (count,))
   
    def search_line(self,srch,srch_neg,gid_list=None):
    
        # set line search criteria
        self.analyzer.set_line_search(srch,srch_neg)
        
        tasks_to_search_in = self.task_db_list
        if gid_list:
            tasks_to_search_in = gid_list
        
        for gid in tasks_to_search_in:
            if gid in self.task_db:
                logger_analyzer.debug("... searching in GID %s, expression '%s'" % (gid,srch))
                task_data = self.task_db[gid]
                self.analyzer.search_line(task_data)
            else:
                logger_analyzer.debug("... searching GID %s: not found in the database" % (gid,))
        
        logger_analyzer.info("Search resulted in %d tasks found." % (len(self.analyzer.line_search_result),))
        return self.search_line_result()
    
    def search_line_result(self):
        return self.analyzer.line_search_result

    def search_chain(self,chsearch):
        r = self.analyzer.search_chain(chsearch)
        suf = self.chsearch_suffix
        if not suf:
            suf = "CHAIN"
        else:
            suf = "CHAIN." + suf

        #pprint(r)

        # this will normalize someday: currently only PER chain lists will be 
        # ordered chronologically
        norm = {}

        for ch in r.keys():
            logger_analyzer.debug("search_chain: result key: \n" + str(ch))
            j = -1
            for i in r[ch]:
                j += 1
                for ch_n in i.keys():
                    norm_key = "%s : %s[%d]" % (ch,ch_n,j)
                    norm_val = r[ch][j][ch_n]
                    
                    norm[norm_key] = norm_val
                    
                    logger_analyzer.debug("search_chain norm key: \n" + str(norm_key))
                    logger_analyzer.debug("search_chain norm val: \n" + str(norm_val))

        f = open_file(self.ca_log,suf)
        if f:
            nl = self.write_tasks(f,norm)
            f.close()
            logger_analyzer.info("[D] %d non-empty lines written to the file" % (nl,))
            return True

        return False    
    
    
    def get_task(self, gid):
        if gid not in self.task_db.keys():
            return None
        return self.task_db[gid]
    

    def workers(self):
        """
        workers: generator iterating all pids available
        """        

        for w in self._workers:
            yield self._workers[w]
    
    def _update_worker(self, pid, line):
        if pid not in self._workers.keys():
            self._workers[pid] = Worker(pid,self)
        
        self._workers[pid].update(line)
        
        return True
    
    def finish(self):
        for w in self._workers:
            self._workers[w].handle_finish()
        
    def proc_line(self,line_raw):

        line = line_raw.strip()
        m = r_line_start.match(line)
        
        if m:
            #p = m.group('pid')
            #if p == 688:
            #    logger_state.info("processing<%s>: " % (p,) + line)
                
            return self._update_worker(m.group('pid'),line)
            
        else:
            if not line:
                logger_state.debug("ignoring blank line")
            else:
                logger_state.warning("ignoring non-conforming line: '%s'" % (line,))
        
        return None
    
    def print_stats(self):
        for k in self._workers.keys():
            w = self._workers[k]
            logger_state.info(k,len(w.log))

    def write_tasks(self,f,task_lists={},prefix_lines=True,prefix_lists=True):      
        ts = task_lists
        labels = "'"
        lines_written = 0
        
        if not task_lists: 
            #logger_state.info('write_task: dumping whole database')
            #ts = {"database dump": self.task_db_list}
            
            logger_state.info('write_task: no data to be written')
            return 0
        
        dot_counter = time.time()
        
            
        
        for ts_l in ts.keys():

            if time.time() - dot_counter > 10 and not self.output_stdout:
                logger_state.info('%d lines written ...' % (lines_written,))
                dot_counter = time.time()

            
            if prefix_lists:
                l_w = "0-0 %s\n" % (ts_l,)
                l_w += "0-0 >>>\n"
                f.write(l_w)
                lines_written += 1
                
            for t_id in ts[ts_l]:
                # because we are appeding gids (t_id here) immediatelly as they appear in the log,
                # we are not sure if the db was filled
                if t_id in self.task_db.keys():
                    logger_state.debug("write_task: GID %s, prefix:%s" % (t_id,str(prefix_lines)))
                    for l in self.task_db[t_id]['log']:
                        l_w = l + "\n"
                        if prefix_lines: l_w = t_id + " " + l + "\n"

                        logger_state.debug("write_task: line to write: '%s'" % (l_w,))
                        f.write(l_w)

                        # likely in interactive mode
                        if self.output_stdout:
                            logger_plain.info(l_w);
                            
                        lines_written += 1
                    
                    if "anno" in self.task_db[t_id].keys():
                        for a in self.task_db[t_id]["anno"]:
                            l_w = Analyzer.annotate_format(a) + '\n'

                            logger_state.debug("write_task: annotation line to write: '%s'" % (l_w,))
                            f.write(l_w)
                            
                    if prefix_lines:
                        f.write("\n\n")
                        
        return lines_written


class Analyzer:
    
    DEBUG_MATCH = 0
    anno_messages = {}
    anno_messages["called_delay"] = "Called request took too long to process"
    anno_messages["called_recv_queue_start"] = "All workers are now busy, starting to queue"
    anno_messages["called_recv_queue_stop"] = "Workers busy state ceased"
    anno_messages["ntlm_big_delay"] = "NTLM request took too long to process"
    anno_messages["ntlm_no_type3"] = "No TYPE3 has been received from Fortigate or browser"
    anno_messages["ntlm_type1_cxfail"] = "NTLM TYPE2 negotiation failed"
    anno_messages["ntlm_type3_cxfail"] = "NTLM TYPE3 validation failed"

    
    def __init__(self,workers):
        self.workers = workers
        self.tasks_by_chrono = {}
        self.tasks_by_role = {}
        
        # if the search is needed, this will store a list of gids
        self.line_search_result = []
        
        # if the chain search is done,  this will store the result
        self.chain_search_result = {}
        
        # chains of gid's by their purpose
        self.chain = {}
        # key points to a list of GIDs, as they appeared in the log, relevant to 'called' ID -- this is logon event id number assigned by receiving thread worker
        # example: self.chain['called']['444322'] = [... list of relevant task gids ... in case of called list will contain e.g. 12312-0-2344, 8902-0-6720 ]
        
        # annotation database, will be filled task_id's 
        # First phase: list by severity
        # contains always list of task_id's 
        self.anno_db = {}
        self.anno_db["severity"] = {}
        self.anno_db["severity"]["ERROR"] = []
        self.anno_db["severity"]["WARNING"] = []
        self.anno_db["severity"]["INFO"] = []
        
        # allow some sort of intermediate result cache
        self.temp = {}

        self.r_workers_busy_test = re.compile(line_start+r'(?P<type>[\w]+) packet: add to queue, called:\d+, current:(?P<count>[\d]+)')
        
        # non-virtual (real) keys present in the regex groups. You can add virtual ones later by mapping
        self.chain_keys = ['called','ip1','ip2','wksta','domain','user','dc_ip','ntlm_seq'] 
        for _k in self.chain_keys:
            self.chain[_k] = {}

        self.debug_zoom = {}
        self.debug_zoom['called'] = []
        self.debug_zoom['ntlm_seq'] = []
    
    
    def data(self):
        ret = {}
        ret["tasks_by_chrono"] = self.tasks_by_chrono
        ret["tasks_by_role"] = self.tasks_by_role
        ret["line_search_result"] = self.line_search_result
        ret["chain"] = self.chain
        ret["chain_keys"] = self.chain_keys
        ret["chain_search_result"] = self.chain_search_result
        ret["anno_db"] = self.anno_db
        ret["debug_zoom"] = self.debug_zoom
        
        return ret
    
    """
        Annotations concept
        task structure will be equipped with the key "anno" which will be a *list*
        of structures:
        {
          "severity": string: [ INFO,WARNING,ERROR ]
          "start": int: index of line where the problem was detected, 0 means it belongs to whole task
          "stop":  int: index of last line relevant to the annotation, 0 means anno relates to start line only
          "message": string: key to global message index, if value is not found, key is written as annotation 
          "details": string: detailed information which cannot be prepared before
          "origin": string
        }
        
        Annotations are written to file under the task log, prefixed with comment string '# ' in form:
        #34534-0-123; ERROR; Lines 23,0; DNS resolution failed in logon; workstation XYZ with user ABC was not logged in
    """
    
    @staticmethod
    def annotate_format(anno_dict):
        return ("#%s -- %s; %s; %s,%s; %s; %s" % (
                str(anno_dict["origin"]),
                str(anno_dict["module"]),
                str(anno_dict["severity"]),
                str(anno_dict["start"]),
                str(anno_dict["stop"]),
                str(anno_dict["message"]),
                str(anno_dict["details"])
                ))
                
    def annotate(self,task_id,module,severity,msg_key,l1=0,l2=0,details=None):
        if "anno" not in self.workers.task_db[task_id].keys():
            self.workers.task_db[task_id]["anno"] = []

        a1 = {}
        a1["module"] = module
        a1["severity"] = severity
        a1["start"] = l1
        a1["stop"] = l2

        try:
            a1["message"] = self.anno_messages[msg_key]
        except KeyError, e:
            a1["message"] = msg_key
        if details:
            a1["details"] = details
        else:
            a1["details"] = "N/A"
        
        a1["origin"] = task_id
        
        self.workers.task_db[task_id]["anno"].append(a1)
        self.anno_db["severity"][severity].append(a1['origin'])
        
        logger_analyzer.debug("[anno] annotating task %s: %s" % (task_id,Analyzer.annotate_format(a1)))
    
    @staticmethod
    def debug_lines(func_name, dict_to_print):
        lines = pformat(dict_to_print).split('\n')
        for l in lines:
            logger_analyzer.debug(func_name+": "+l)
    
    def print_chain(self):
        for ch in self.chain.keys():
            logger_analyzer.info(">>>")
            logger_analyzer.info(">>> CHAIN: '%s'" % (ch,))
            logger_analyzer.info(">>>")
            for k in self.chain[ch].keys():
                list_len = len(self.chain[ch][k])
                logger_analyzer.info("... entry: '%s' len:%d" % (k,list_len))
                t = ""
                for gid in self.chain[ch][k]: t+= "%s " % (gid,)
                logger_analyzer.info("... ... values: %s" % (t,))
            
    
    
    def add(self,task_data):
        task_data['analyzer'] = {}
        task_data['analyzer']['status'] = 'incomplete'
        task_data['analyzer']['severity'] = 'none'
        
        self.task_by_chrono["%s-%s" % (task_data['pid'],task_data['id'])] = task_data
        self.task_by_role[task_data[role]].append(task_data)

    def search_chain(self, chsearch, strategy='ANY'):
        logger_analyzer.warning("This is code under active development and is subject of instability and change")

        criteria = {}
        for cr in chsearch:
            key,typ,ex = None,None,None
            
            try:
                key,typ,ex = cr.split(":",2)
            except ValueError:
                logger_analyzer.error("Uknown criteria format: %s" % (cr,))
                return {}
                
            if not typ: typ = "rxi"
            #pprint([key,typ,ex])

            if key not in criteria.keys(): criteria[key] = []
            criteria[key].append([typ,ex])
            #criteria = Analyzer.stack_dict(criteria,{key:[typ,ex]},unique=False)

        logger_analyzer.debug("search_chain: criteria:")
        Analyzer.debug_lines("search_chain",criteria)

        matches = {}

        # iterating criteria first, all of the same key have to succeed (e.g. c = 'ip')
        for c in criteria.keys():


            if c not in self.chain.keys():
                logger_analyzer.warning("chain search: criteria key '%s' not found. Ignoring." % (c,))
                continue

            matches_this_criteria = True

            cur = None

            # match 
            for k in self.chain[c]:
                cur = k
                matches_this_criteria = True

                # iterate through criteria list (e.g. criteria[c] = [('ex','1.1.1.1'),('rxi','1.1.1.[0-1]')]), all of the same type must succeed, it's ALL match
                for crit_lst in criteria[c]:
                    typ = crit_lst[0]
                    ex = crit_lst[1]

                    m = None
                    if typ == 'rx':
                        # case sensitive regex 
                        m = re.search(ex,k)
                    elif typ == 'rxi':
                        # case insensitive regex  (DEFAULT)
                        m = re.search(ex,k, flags=re.IGNORECASE)
                    elif typ == 'ex':
                        # exact match
                        m = ( ex == k )
                    elif typ == 'exi':
                        # exact match case insensitive
                        m = ( ex.lower() == k.lower())
                    elif typ == 'ip':
                        try:
                            ex_ip = ipaddr.IPv4Network(ex)
                            k_ip = ipaddr.IPv4Address(k)
                            m = ( k_ip in ex_ip )
                        except ValueError:
                            logger_analyzer.warning('search_chain: address/netmask is invalid: %s,%s' % (ex,k))
                            # falling back to exact non-sensitive match
                            m = ( ex == k.lower())

                    if m:
                        if strategy=='ALL':
                            logger_analyzer.debug("partial match: ('%s' matches '%s' expression '%s')" % (k,typ,ex))
                        else:
                            # strategy=="ANY"
                            logger_analyzer.debug("sufficient match: ('%s' matches '%s' expression '%s')" % (k,typ,ex))
                            matches_this_criteria = True
                            break
                    else:
                        matches_this_criteria = False
                        

                if matches_this_criteria and cur:
                    # all of the same criteria key matched
                    logger_analyzer.info("successful match: %s" % (cur,))
                    matches = Analyzer.normalize_dict_values(Analyzer.stack_dict(matches, { c:{ cur: self.chain[c][cur] }}))

        Analyzer.debug_lines("search_chain[result]",matches)

        #'ex - exact, rx - regex, rxi - regex insensitive, ip - ip based search'

        # 
        self.chain_search_result = matches
        return matches  


    def normalized_search_chain(self):
        """
        look into self.chain, and comparing to chronological workers task_list,
        create ordered results.
        """
        if not self.chain_search_result:
            return []
        
        # list of gids appearing in the search_chain result
        chain_gids = []
        
        # flatten the chain search result in row of events and fill chain_gids
        for chain in self.chain_search_result.keys():
            for chain_name in self.chain_search_result[chain].keys():
                chain_gids.extend(self.chain_search_result[chain][chain_name])
        
        chrono_chain_gids = []
        for gid in self.workers.task_db_list:
            if gid in self.workers.task_db.keys():
                if gid in chain_gids:
                    # yes, this gid is in the chain search
                    chrono_chain_gids.append(gid)
                    
        return chrono_chain_gids
        

    def set_line_search(self,srch, srch_neg):
        self.line_search = srch
        self.line_search_neg = srch_neg

    def search_line(self,task_data):
        """
        search in the task content and match the task if ANY line matches the one expression
        in 'srch' list. ALL 'srch' expressions have to match, in order the task to be
        match candidate.
        All lines are also matched against ALL srch_neg expressions. If ANY match 
        succeed, then the candidate is considered NOT MATCHING.
        
        mode: 0=regular expression (FIXME: more to come? .. but why? ;-)
        """
        
        srch = self.line_search
        srch_neg = self.line_search_neg
        
        result = {}
    
        batch = []
        batch.extend(srch)
        if srch_neg:
            batch.extend(srch_neg)
    
        for s in batch:
            i = 0
            for l in task_data['log']:
                #logger_analyzer.debug("Searching ALL '%s' and not ANY '%s' in '%s'" % (str(srch),str(srch_neg),l))
                m = re.search(s,l,flags=re.IGNORECASE)
                if m:
                    gid = task_data['gid']
                    role = task_data['role']
                    
                    result[s] = i
                    break
        
                i+=1

        
        positive = True
        for p in srch:
            if p not in result.keys():
                positive = False
                break
        
        negative = False
        if srch_neg:
            for n in srch_neg:
                if n in result.keys():
                    negative = True
                    break
            
        if positive and not negative:
            logger_analyzer.debug("Task '%s' with role '%s' matches search criteria" % (gid,role))
            self.line_search_result.append(gid)
            return True
        
        return False
        
                
        
    # go and analyze
    def analyze_task(self, task_data):
        """
        Crossroad function which is utilized to let analyze the task, according to
        it's role
        """
        
        # enrich task_data with analyzer entry
        task_data['an'] = {}
        
        if task_data['role']==Worker.ROLE_DCAGENTIORECV:
            logger_analyzer.debug('analyzing msg from dcagent: taskid=%s' % (task_data['id'],))
            result = self.analyze_dcagent_msg(task_data)
            self.update_chain(result)
        
        elif task_data['role']==Worker.ROLE_FGTIORECV:
            logger_analyzer.debug('analyzing msg from fortigate: taskid=%s' % (task_data['id'],))
            result = self.analyze_fortigate_io_msg(task_data)
            self.update_chain(result)
            
    
        elif task_data['role']==Worker.ROLE_LOGONS:
            logger_analyzer.debug('Starting to analyze logon task')
            result = self.analyze_logons(task_data)
            self.update_chain(result)
        elif task_data['role']==Worker.ROLE_UPDATERWKS:
            logger_analyzer.debug('Starting to analyze workstation check task')
            result = self.analyze_wksta_check(task_data)
            self.update_chain(result)
        elif task_data['role']==Worker.ROLE_FGTMSG:
            logger_analyzer.debug('Starting to analyze workstation check task')
            result = self.analyze_fortigate_msg(task_data)
            self.update_chain(result)     
        elif task_data['role']==Worker.ROLE_UPDATERIP:
            logger_analyzer.debug('Starting to analyze ip check task')
            result = self.analyze_ip_check(task_data)
            self.update_chain(result)
        elif task_data['role']==Worker.ROLE_DOPOLL:
            result = self.analyze_poller(task_data)
            self.update_chain(result)
        else:
            pass
            #logger_analyzer.error('Unknown task role: %s' % (task_data['role'],))
    
    def analyze_poller(self, task_data):
        gid = task_data['gid']
        result = {}
        result['gid'] = gid
    
        for l in task_data['log']:
            m = r_func_poller_login.match(l)
            if m:
                logger_analyzer.debug("analyze_poller: matched func_poller_login")
                r = m.groupdict()

                r['dc_ip'] = Analyzer.hexip_to_str(r['dc_ip'])
                
                if re.match('\d+\.\d+\.\d+\.\d+',r['wksta']):
                    logger_analyzer.debug("analyze_poller: wksta in form of IP adress")
                    r['ip1'] = r['wksta']
                
                result = Analyzer.stack_dict(result,r)
            
        return result
    
    
    def analyze_dcagent_msg(self, task_data):
        """
        Analyzing and chaining the messages of DCAgent 
        """
        
        gid = task_data['gid']
        result = {}
        result['gid'] = gid
    
        for l in task_data['log']:
            m = r_func_dcagent_msg_received.match(l)
            if m:
                c = m.group('called')
                logger_analyzer.debug("analyze_dcagent_msg: matched msg_received")
                #if c in self.chain['called'].keys():
                #    logger_analyzer.debug('analyze_dcagent_msg: called ID %s alrady processed! Skipping.' % (c,))
                #    continue
                #
                #result['called'] = c
                result = Analyzer.stack_dict(result,{'called':c})

                # add 'called' into analyzer stack 
                if ('called' in m.groupdict().keys()):
                    task_data['an']['called'] = m.groupdict()['called']


        return result
    
    def analyze_fortigate_io_msg(self,task_data):
        gid = task_data['gid']
        result = {}
        result['gid'] = gid
    
        for l in task_data['log']:
           
            m = r_func_fortigate_io_ntlm_req.match(l)
            if m:
                 # update the result dict by the match
                logger_analyzer.debug("analyze_fortigate_msg: func_fortigate_io_ntlm_req: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                
                # add 'called' into analyzer stack 
                if ('called' in m.groupdict().keys()):
                    task_data['an']['called'] = m.groupdict()['called']
                
                continue   
                
        return result
        
        
    def analyze_logons(self,task_data):
        """
        Analyzing and chaining logon event messages
        """
        
        gid = task_data['gid']
        result = {}
        result['gid'] = gid
        
        LOGON_NTLM = False
        
        for l in task_data['log']:      
                  
            # match the very first meaningful log line
            # e.g.
            # dcagent packet: removed from queue, called:1428633 remain:0
            m = r_func_dcadgent_remove_q.match(l)
            if m:
                c = m.group('called')
                
                # add 'called' into analyzer stack 
                if ('called' in m.groupdict().keys()):
                    task_data['an']['called'] = m.groupdict()['called']
                    logger_analyzer.debug("analyze_logons: r_func_dcadgent_remove_q: [called]: %s" % (task_data['an']['called'],))

          
                if c not in self.chain['called'].keys():
                    logger_analyzer.debug("analyze_logons: called ID '%s' not found! Skipping." % (c,))
                    # FIXME: this could be handled more elegant way: the logon event which cannot be paired 
                    # will be marked as <incomplete>
                    continue
      
                if 'called' not in result: result = Analyzer.stack_dict( result, {'called':c})
                continue

            
            m = r_func_ntlm_remove_q.match(l)
            if m:
                
                LOGON_NTLM = True
                
                c = m.group('called')
                
                # add 'called' into analyzer stack 
                if ('called' in m.groupdict().keys()):
                    task_data['an']['called'] = m.groupdict()['called']
                    logger_analyzer.debug("analyze_logons: : r_func_ntlm_remove_q: [called]: %s" % (task_data['an']['called'],))
                
                
                if c not in self.chain['called'].keys():
                    logger_analyzer.debug("analyze_logons: called ID '%s' not found! Skipping." % (c,))
                    # FIXME: this could be handled more elegant way: the logon event which cannot be paired 
                    # will be marked as <incomplete>
                    continue
                
                if 'called' not in result: result = Analyzer.stack_dict( result, {'called':c})
                continue                
                
            # match logon event with extra IP -- MATCH BEFORE without extra
            # logon event(1428633): len:49 dc_ip:10.81.0.41 time:1359606186 len:32 
            #        data:NB0036.lpti.le.grp/PC_D01/TPT090 ip:10.81.12.110:10.81.3.163
            m = r_func_logon_event_ex.match(l)
            if m:
                logger_analyzer.debug("analyze_logons: func_logon_event_1 [extra ip]: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                #pprint(m.groupdict())
                continue
                
            # match logon event with single IP, eg
            # e.g.
            # logon event(1428635): len:43 dc_ip:10.81.0.41 time:1359606186 len:31 
            #        data:T1288.lpti.le.grp/PC_D01/TPT009 ip:10.81.10.67
            m = r_func_logon_event.match(l)
            if m:
                # update the result dict by the match
                logger_analyzer.debug("analyze_logons: func_logon_event: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue
           
            # 
            m = r_func_new_logon_0.match(l)
            if m:
                # update the result dict by the match
                logger_analyzer.debug("analyze_logons: func_new_logon_0: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue     
                
            m = r_func_new_logon_1.match(l)
            if m:
                # update the result dict by the match
                logger_analyzer.debug("analyze_logons: func_new_logon_1: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue         
            
            m = r_func_dns_query.match(l)
            if m:
                # update the result dict by the match
                logger_analyzer.debug("analyze_logons: func_dns_query: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue         
            
            m = r_func_dns_cannot_resolve.match(l)
            if m:
                # update the result dict by the match
                logger_analyzer.debug("analyze_logons: func_dns_cannot_resolve: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue         
            

            # ANALYZE NTLM LOGON EVENT
            if LOGON_NTLM:
                m = r_func_ntlm_user.match(l)    
                if m:
                    # update the result dict by the match
                    logger_analyzer.debug("analyze_logons: func_ntlm_user: %s" % (l,))
                    #result.update(m.groupdict())
                    result = Analyzer.stack_dict(result,m.groupdict())
                    continue         

                m = r_func_ntlm_wksta.match(l)    
                if m:
                    # update the result dict by the match
                    logger_analyzer.debug("analyze_logons: func_ntlm_wksta: %s" % (l,))
                    #result.update(m.groupdict())
                    result = Analyzer.stack_dict(result,m.groupdict())
                    continue         

                m = r_func_ntlm_domain.match(l)    
                if m:
                    # update the result dict by the match
                    logger_analyzer.debug("analyze_logons: func_ntlm_domain: %s" % (l,))
                    #result.update(m.groupdict())
                    result = Analyzer.stack_dict(result,m.groupdict())
                    continue         
                m = r_func_ntlm_seq.match(l)
                if m:
                    # update the result dict by the match
                    logger_analyzer.debug("analyze_logons: func_ntlm_seq: %s" % (l,))
                    #result.update(m.groupdict())
                    result = Analyzer.stack_dict(result,m.groupdict())
                    continue         
                
                
                
        #pprint(result)
        return result

    def analyze_wksta_check(self,task_data):
        """
        """ 
        gid = task_data['gid']
        result = {}
        result['gid'] = gid
        
        for l in task_data['log']:
            m = r_func_update_entry_workstation.match(l)
            if m:
                logger_analyzer.debug("analyze_wksta_check: func_update_entry_workstation: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue
            
            m = r_func_wksta_verify_ip.match(l)
            if m:
                logger_analyzer.debug("analyze_wksta_check: func_wksta_verify_ip: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue
         
            # important thing is revealed: SID
            m = r_func_wksta_test.match(l)
            if m:
                logger_analyzer.debug("analyze_wksta_check: func_wksta_test: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue
         
        return result

    def analyze_fortigate_msg(self,task_data):
        gid = task_data['gid']
        result = {}
        result['gid'] = gid
        
        logon_users = []
        logoff_users = []
        
        line = -1
        for l in task_data['log']:
            line += 1
            m = r_func_fortigate_msg_cache_logon_send.match(l)
            if m:
                logger_analyzer.debug("analyze_fortigate_msg: func_fortigate_msg_cache_logon_send: %s" % (l,))
                continue
                
            m = r_func_fortigate_msg_cache_logoff_purge.match(l)
            if m:
                logger_analyzer.debug("analyze_fortigate_msg: func_fortigate_msg_cache_logoff_purge: %s" % (l,))
                continue
            
            m = r_func_fortigate_msg_cache_logon_user.match(l)
            if m:
                logger_analyzer.debug("analyze_fortigate_msg: func_fortigate_msg_cache_logon_user: %s" % (l,))
                user1 = m.group('user1')
                user2 = m.group('user2')
                logon_users.append(user2)
                logoff_users.append(user1)
                result = Analyzer.stack_dict(result,{'user': [user1,user2]})
                continue
                
            m = r_func_fortigate_msg_cache_logoff_user.match(l)
            if m:
                logger_analyzer.debug("analyze_fortigate_msg: func_fortigate_msg_cache_logoff_user: %s" % (l,))
                
                # FIXME: this is the new-style debug dump, spread it
                if Analyzer.DEBUG_MATCH: 
                    Analyzer.debug_lines("func_fortigate_msg_cache_logoff_user",m.groupdict())
                result = Analyzer.stack_dict(result, m.groupdict())
                continue
                
          
        return result


    def analyze_ip_check(self,task_data):
        gid = task_data['gid']
        result = {}
        result['gid'] = gid
        
        for l in task_data['log']:
            m = r_func_update_entry_ip.match(l)
            if m:
                logger_analyzer.debug("analyze_ip_check: func_update_entry_ip: %s" % (l,))
                result = Analyzer.stack_dict(result,m.groupdict())
                # FIXME: clean; some debug outputs
                #Analyzer.debug_lines("func_update_entry_ip",m.groupdict())
                #print gid
                #pprint(m.groupdict())
                #sys.exit(-66)
                continue        
        
        return result

    def update_chain(self,result_struct):    
        """
            walk through all result keys and append keywords to the chains

            result_struct: dict containing data from analyze_* functions. Intention is to fill
                           the database of relation between task and: username, workstation name, etc.
                           to be able at the end to print all tasks related to particular user/ip/wksta.
        """
        
        # map real keys (appearing in the result_struct) to some more reasonable
        # name.
        virtual_map = {}
        # this mapping will keep track on all client IPs regardless it was extra
        # IP sent by the DC agent, or not
        virtual_map['ip1'] = 'ip'
        virtual_map['ip2'] = 'ip'
        
        # this one is just an example of bad habbits ;)
        virtual_map['called_id'] = 'called'
        
        # use this to filter out values stored in virtual labels
        filter_map = {}
        filter_map['ip'] = ["0.0.0.0",]
        
        # iterate through keys of chain, eg. called_id, wksta, ip1, ip2,...
        # this is pre-filled in the constructor, what we are looking for
        for ch in self.chain_keys:
            
            # if the result_struct should update the key
            if ch in result_struct.keys():
                c = result_struct[ch]
                logger_analyzer.debug("update_analyze_result: adding '%s' into the '%s' chain" % (str(c),ch))
                
                
                # the return value should be always a list! (starting from 1.1a)
                if type(c) != type([]):
                    logger_analyzer.info("ASSERTION FAILED: %s is not the list => converting" % (c,))
                    c = [c,]
                
                logger_analyzer.debug("update_analyze_result: %d values to the chain '%s'" % (len(c),ch))
                for c_ix in c:
                    c_i = c_ix.lower()
                    # init chain, if it's empty
                    if c_i not in self.chain[ch].keys(): self.chain[ch][c_i] = []

                    # update the chain with task GID -- this GID contains reference to the keyword, but only 
                    # if it's not there already => avoid duplicates
                    if result_struct['gid'] not in self.chain[ch][c_i]:
                        self.chain[ch][c_i].append(result_struct['gid'])
                    
                    # init chained in task_data
                    if 'chains' not in self.workers.task_db[result_struct['gid']].keys():
                        self.workers.task_db[result_struct['gid']]['values'] = {}
                    Analyzer.stack_dict(self.workers.task_db[result_struct['gid']]['values'],result_struct)
                    
                
                # virtual map processing!
                
                if ch in virtual_map:
                    logger_analyzer.debug("update_analyze_result: mapping expresion '%s' into '%s' "
                                % (ch,virtual_map[ch]))
                    
                    # init the virtually mapped entries in the chain
                    if virtual_map[ch] not in self.chain.keys(): self.chain[virtual_map[ch]] = {}
                    
                    logger_analyzer.debug("update_analyze_result: %d values to mapped '%s'" % (len(c),virtual_map[ch]))
                    for c_ix in c:
                        c_i = c_ix.lower()
                        if c_i not in self.chain[virtual_map[ch]]: self.chain[virtual_map[ch]][c_i] = []

                        # this value is filtered out from storing into the chain
                        if virtual_map[ch] in filter_map:
                            if c_i in filter_map[virtual_map[ch]]:
                                continue

                        # update the chain with task GID -- this GID contains reference to the keyword, but only 
                        # if it's not there already => avoid duplicates
                        if result_struct['gid'] not in self.chain[ch][c_i]:
                            self.chain[virtual_map[ch]][c_i].append(result_struct['gid'])

                        # init chained in task_data
                        if 'chains' not in self.workers.task_db[result_struct['gid']].keys():
                            self.workers.task_db[result_struct['gid']]['values'] = {}

                        # now we have results also in task_data. Dont repeat items in the list, normalize result!
                        Analyzer.stack_dict(self.workers.task_db[result_struct['gid']]['values'],result_struct)
                    
            else:
                logger_analyzer.debug("regex group '%s' not present in the task '%s'" 
                        % (ch,result_struct['gid']))
    
    
    
    
    @staticmethod
    def normalize_dict_values(d):
        if type(d) != type({}):
            return d
        
        for k in d.keys():
            cur_item = d[k]

            if type(cur_item) == type([]):
                try:
                    conv_list = []
                    for item in cur_item:
                        if item not in conv_list:
                            conv_list.append(item)
                            
                    logger_analyzer.debug("normalize_dict_values: Converting list: %s -> %s", str(cur_item), str(conv_list))
                    d[k] = conv_list
                except TypeError, e:
                    # ignore lists of complex types
                    pass
            
            elif type(cur_item) == type({}):
                conv_dict = normalize_dict_values(cur_item)
                d[k] = conv_dict
                
        
        return d
    
    @staticmethod
    def stack_dict(d, d_add,unique=True):
        """
        Enrich dict with more values in keyed lists:       
        this is assuming the usage of dict, containing key->[list_of_values]
        Example:
        
        d = {
            "ip1":["1.1.1.1","1.1.1.2"]
            "wksta":"example"
        }
        
        a = {
            "ip1":"2.2.2.1"
        }
        
        d = Analyzer.stack_dict(d,a)
        
        # d will be set to:
        { 
            "ip1":["1.1.1.1","1.1.1.2","2.2.2.1"]
            "wksta":"example"
        }
                
        
        this dict will be updated, but by extending lists inside a dict, not replacing them
        d: dict to be stacked
        d_add: dict with updates
        unique: if set (by default), the value will not be added if already there

        FIXME: problem when stacking sets into the returned list 
        """
        
        # iterate what to stack
        for k_add in d_add.keys():
            
            # when what to stack is already there
            if k_add in d.keys():
                
                # CURRENT DICT NORMALIZATION
                # grab the already stored values in 'v'
                v = d[k_add]                
                # if 'v' is not list, it should be converted to a list
                if type(v) != type([]):
                    d[k_add] = [v,]

                # ADDING TO THE DICT DEPENDING ON THE ADDITION TYPE
                # if the addition is not a list, we can just append
                if type(d_add[k_add]) != type([]):
                    # addition is already in values, but unique is not set => store
                    if d_add[k_add] in d[k_add] and not unique:
                        d[k_add].append(d_add[k_add])
                    
                    # addition is not there
                    elif  d_add[k_add] not in d[k_add]:
                        d[k_add].append(d_add[k_add])
                
                # id the addition is the list, we want to append IT'S VALUES (not the list itself)
                else:
                    # so iterate through the addition
                    for to_add in d_add[k_add]:
                        # if the addition item is there but unique is not set => store
                        if to_add in d[k_add] and not unique:
                            d[k_add].append(to_add)
                        
                        # if the addition item is not there
                        elif to_add not in d[k_add]:
                            d[k_add].append(to_add)
            
            # when what to stack is not there
            else:
                # if it's not the list, then create list and assign
                if type(d_add[k_add]) != type([]):
                    d[k_add] = [d_add[k_add],]
                else:
                    # if it's a list, then just assign
                    d[k_add] = d_add[k_add]
        return d
    
    @staticmethod
    def strptime(s):
        return datetime.datetime.strptime(s, "%m/%d/%Y %H:%M:%S")

    @staticmethod
    def line_timedelta(l1,l2):
        m1 = re.search("^"+line_start,l1)
        m2 = re.search("^"+line_start,l2)

        logger_analyzer.debug("line_timedelta: t1=%s" % (pformat(m1.group('timestamp')),))
        logger_analyzer.debug("line_timedelta: t2=%s" % (pformat(m2.group('timestamp')),))
        
        if m1 and m2:
            delta = Analyzer.strptime(m2.group('timestamp')) -  Analyzer.strptime(m1.group('timestamp'))
            logger_analyzer.debug("delta=%.2f" % (delta.total_seconds(),))
            
            # DEP: 2.7
            return delta.total_seconds()

        return None
    
    
    @staticmethod
    def task_delay(t1, t2):
        #return Analyzer.line_timedelta(t1['log'][-1],t2['log'][0])
        return Analyzer.line_timedelta(t1['log'][0],t2['log'][-1])

    @staticmethod
    def task_begin(t):
        l = t['log'][0]
        m = re.search("^"+line_start,l)
        
        if m:
            return m.group('timestamp')
        
        return None

    @staticmethod
    def task_end(t):
        l = t['log'][-1]
        m = re.search("^"+line_start,l)
        
        if m:
            return m.group('timestamp')
        
        return None

    @staticmethod    
    def hexip_to_str(t):

        ip4 = int(t[0:2],16)
        ip3 = int(t[2:4],16)
        ip2 = int(t[4:6],16)
        ip1 = int(t[6:8],16)

        return  "%d.%d.%d.%d" % (ip1,ip2,ip3,ip4)
    
    
    @staticmethod
    def chain_delays(task_list):
        l = len(task_list)
        r = []
        for x in xrange(0,l-1):
            r.append( Analyzer.task_delay(task_list[x], Analyzer.task_list[x+1]))
        
        return r
        
    def analyze_chain_called(self):
        logger_analyzer.debug("[called]... processing 'called' chain: start")
        
        # operate on sorted list to have it in order
        for c in sorted(self.chain['called']):
            logger_analyzer.debug("[called]... processing 'called' ID: %s" % (c,))

            if len(self.chain['called'][c]) >= 1:
                t1 = self.chain['called'][c][0]
                self.analyze_chain_called_queue(t1)
                
            # FIXME: testing ... just length of 2 is processed, others silently ignored
            if len(self.chain['called'][c]) >= 2:
                t1 = self.chain['called'][c][0]
                t2 = self.chain['called'][c][-1]
                
                if c in self.debug_zoom['called']:
                    logger_analyzer.info("Task: %s" % (t1,))
                    for l in self.workers.task_db[t1]['log']:
                        logger_analyzer.info(l)
                    logger_analyzer.info("Task: %s" % (t2,))
                    for l in self.workers.task_db[t2]['log']:
                        logger_analyzer.info(l)

                
                # sometimes it happen that in the chain the first task will finish later
                # than the others. It can give negative results. Abs it.
                
                d =  abs(Analyzer.task_delay(self.workers.task_db[t1],self.workers.task_db[t2]))
                
                # FIXME: those messages should be set to approriate level!!!
                #        ... but also on appropriate place, stdout it's not appropriate place
                
                if d > 5:
                    logger_analyzer.debug("[called] Called ID %s: delayed = %.2f" % (c,d))
                    det="Processing took %.0f seconds (related tasks %s,%s)" % (d,t1,t2)
                    self.annotate(t1,"CALLED","WARNING","called_delay",details=det)
                    self.annotate(t2,"CALLED","WARNING","called_delay",details=det)
              
            
        
        logger_analyzer.debug("[called]... processing 'called' chain: done")

    def analyze_chain_called_queue(self,tid):
        
        for l in self.workers.task_db[tid]['log']:
            m = self.r_workers_busy_test.match(l)

            if m:
                # count = current possition in the queue 
                count = m.groupdict()['count']
                
                # init cache if necessary
                if "called_recv_queue" not in self.temp.keys():
                    self.temp['called_recv_queue'] = 0
                
                if int(count) > 0 and self.temp['called_recv_queue'] == 0:
                    self.temp['called_recv_queue'] = int(count)
                    self.temp['called_recv_queue_tid'] = tid

                elif int(count) == 0 and self.temp['called_recv_queue'] > 0:
                    self.temp['called_recv_queue'] = int(count)
                    start_tid = self.temp['called_recv_queue_tid']
                    d = abs(Analyzer.task_delay(self.workers.task_db[start_tid],self.workers.task_db[tid]))

                    if d > 5:
                        sev = "WARNING"
                        if d > 20:
                            sev = "ERROR"
                            
                        det = "Check previous called IDs what is taking so long. Consider raising workerthreadcount and group cache!"
                        self.annotate(start_tid,"CALLED",sev,"called_recv_queue_start",details=det)

                        det = "Busy state took %.0f seconds." % (d,)
                        self.annotate(tid,"CALLED",sev,"called_recv_queue_stop",details=det)
                    
        

    def analyzer_chain_ntlm_log_seq(self,c,msg=None,content=True):

        m = ""
        if msg:
           m = msg 
            
        logger_analyzer.warning("[ntlm] [note]  ID "+c+": "+m)

        if content: 
            logger_analyzer.warning(pprint(self.chain['ntlm_seq'][c]))
            for cc in self.chain['ntlm_seq'][c]:
                logger_analyzer.info(pprint(self.workers.task_db[cc]))        
        
            logger_analyzer.warning("--- ")
        
    
    def analyze_chain_ntlm_seq(self):
        logger_analyzer.debug("[ntlm]... processing 'ntlm_seq' chain: start")   
        
        if len(self.chain['ntlm_seq'].keys()) == 0:
            return
        
        ntlm_not_received = []
        ntlm_received = []
        ntlm_received_deltas = []
        ntlm_error = []
        
        for c in self.chain['ntlm_seq'].keys():

            logger_analyzer.debug("analyze_chain_ntlm_seq: processing self.chain['ntlm_seq'][%s]",(str(c),))
            # type1 message - processed
            t1_ntlm1 = self.chain['ntlm_seq'][c][0]
            t1_ntlm1_called = self.workers.task_db[t1_ntlm1]['an']['called']
                        
            # calculate time difference
            l = len(self.chain['ntlm_seq'][c]) 
            if l == 2:

                # type1 message - just arrived - looking for it using 'called' analyzer stack in the task_data
                t1_called1 = None
                
                t2_ntlm2 = self.chain['ntlm_seq'][c][1]
                t2_ntlm2_called = self.workers.task_db[t2_ntlm2]['an']['called']
                t2_end = Analyzer.task_end(self.workers.task_db[t2_ntlm2]).split()[1]
                t2_delta = abs(Analyzer.task_delay(self.workers.task_db[t2_ntlm2],self.workers.task_db[t2_ntlm2]))

                user = "??"
                domain = '??'
                
                try:
                    user = self.workers.task_db[t2_ntlm2]['values']['user'][0]
                    domain = self.workers.task_db[t2_ntlm2]['values']['domain'][0]
                except KeyError:
                    pass
                
                
                if t1_ntlm1_called in self.chain['called'].keys():
                    t1_called1 = self.chain['called'][t1_ntlm1_called][0]
                    #t1_struct = self.workers.task_db[t1]
                    #logger_analyzer.info(str(t1_struct))
                    #return
     
                    d =  abs(Analyzer.task_delay(self.workers.task_db[t1_called1],self.workers.task_db[t2_ntlm2]))
                    t1_begin = Analyzer.task_begin(self.workers.task_db[t1_called1]).split()[1]
                    t1_delta = abs(Analyzer.task_delay(self.workers.task_db[t1_called1],self.workers.task_db[t1_called1]))
                    

                    logger_analyzer.debug("[ntlm]... NTLM ID %s: (t1 queued %s: %s, t3 sent %s: %s) delay %.2f (%.2f,%.2f)" % (c,t1_ntlm1_called,t1_begin, t2_ntlm2_called,t2_end, d,t1_delta,t2_delta))
                    ntlm_received_deltas.append(int(d)) 
                    
                    if(d > 20):
                        t1_called2 = self.chain['called'][t1_ntlm1_called][1]
                        t2_ntlm1 = self.chain['called'][t2_ntlm2_called][0]
                        
                        det = "total processing time for %s\%s is %d seconds (tasks chain %s,%s,%s,%s)" % (domain,user,d,t1_called1,t1_called2,t2_ntlm1,t2_ntlm2)
                        
                        #self.analyzer_chain_ntlm_log_seq(c,"too big delay in processing response!",content=False)
                        self.annotate(t1_called1,"NTLM","WARNING","ntlm_big_delay",details=det)
                        self.annotate(t1_called2,"NTLM","WARNING","ntlm_big_delay",details=det)
                        self.annotate(t2_ntlm1,"NTLM","WARNING","ntlm_big_delay",details=det)
                        self.annotate(t2_ntlm2,"NTLM","WARNING","ntlm_big_delay",details=det)
                        
                        self.analyze_chain_ntlm_type1(t1_called2)
                        self.analyze_chain_ntlm_type3(t2_ntlm2)
                        

                else:
                    logger_analyzer.debug("[ntlm]... NTLM ID %s: (t1 queued %s: %s, t3 sent %s: %s) delay ?? (<?>.%.2f)" % (c,t1_ntlm1_called,'<???>', t2_ntlm2_called,t2_end,t2_delta))
                
                ntlm_received.append(c)
                

            elif l > 2:
                logger_analyzer.warning("[ntlm]... NTLM ID %s: expected 2 entries, got %d" % (c,l))
                ntlm_error.append(c)
            elif l == 1:
	      
	        try:
		    logger_analyzer.debug("[ntlm]... NTLM ID %s: TYPE3 was not received" % (c,))
		    t1_called1 = self.chain['called'][t1_ntlm1_called][0]
		    t1_called2 = self.chain['called'][t1_ntlm1_called][1]
		    det="related tasks %s,%s" % (t1_called1,t1_called2)
		    
		    self.annotate(t1_called1,"NTLM","ERROR","ntlm_no_type3",details=det)
		    self.annotate(t1_called2,"NTLM","ERROR","ntlm_no_type3",details=det)
		    self.analyze_chain_ntlm_type1(t1_called2)
		    
		    ntlm_not_received.append(c)
		except KeyError:
		    pass
        
        
        
        ntlm_received_avg = sum(ntlm_received_deltas,0.0) / len(ntlm_received_deltas)
        ntlm_total = len(ntlm_received)+len(ntlm_not_received)+len(ntlm_error)
        ntlm_failed = len(ntlm_not_received)+len(ntlm_error)
        
        logger_analyzer.info("NTLM statistics:")
        logger_analyzer.info("NTLM statistics: Type3 received: %d [%.2fs avg. delay], only type1 recvd: %d, Error: %d" % 
                        (len(ntlm_received),ntlm_received_avg,len(ntlm_not_received),len(ntlm_error)))
        logger_analyzer.info("NTLM statistics: Total %d, %.2f%% failed" % (ntlm_total,100*float(ntlm_failed)/ntlm_total))


    def analyze_chain_ntlm_type1(self,tid):
 
        #"AcceptSecurityContext failed: 0x80090302"
        cx_failed = re.compile(line_start+r'AcceptSecurityContext failed: (?P<code>0x[\da-f]+)')
        
        for l in self.workers.task_db[tid]['log']:
            #logger_analyzer.info("[D]"+l)
            det = None
            sev = "INFO"

            m = cx_failed.match(l)
            if m:
                err_code = m.groupdict()["code"]
                
                if err_code == "0x80090302":
                    det = "Code: 0x80090302 - Possibly non-domain user? ::: MS TechSupport: SEC_E_UNSUPPORTED_FUNCTION: The function failed. A context attribute flag that is not valid (ASC_REQ_DELEGATE or ASC_REQ_PROMPT_FOR_CREDS) was specified in the fContextReq parameter."
                    sev = "WARNING"
                else:
                    det = "Unknown return code: %s" % (err_code,)
                
                self.annotate(tid,"NTLM",sev,"ntlm_type1_cxfail",details=det)
        

    def analyze_chain_ntlm_type3(self,tid):
        #"AcceptSecurityContext failed: 0x8009030c"
        cx_failed = re.compile(line_start+r'AcceptSecurityContext failed: (?P<code>0x[\da-f]+)')
        
        for l in self.workers.task_db[tid]['log']:
            #logger_analyzer.info("[D]"+l)
            det = None
            sev = "INFO"

            m = cx_failed.match(l)
            if m:
                err_code = m.groupdict()["code"]
                
                if err_code == "0x8009030c":
                    det = "Code: 0x8009030c - Possibly wrong credentails? ::: MS TechSupport: SEC_E_LOGON_DENIED: The logon failed."
                else:
                    det = "Unknown return code: %s" % (err_code,)
                self.annotate(tid,"NTLM",sev,"ntlm_type3_cxfail",details=det)
        

"""
Process the file: process the file and return workers object
"""    
def proc_calog(fnm):
    logger_state.info("Processing file: %s" % (fnm,))
    
    ws = Workers(fnm)
    f = None
    try:
        f = open(fnm)
    except Exception,e:
        logger_state.critical(str(e))
        return None
        
    try:
        ok_count = 0
        er_count = 0
        
        dot_counter = time.time()
        
        for line in f:
            if not ws.proc_line(line): er_count += 1
            else: ok_count += 1
            
            if time.time() - dot_counter > 10:
                logger_state.info('%d lines processed ...' % (ok_count+er_count))
                dot_counter = time.time()
        
        # let's write last tasks for all workers
        ws.finish()
                
            
                
    finally:
        f.close()

    logger_state.info("Done: %d tasks in %d lines, ok=%d, err=%d" % (len(ws.task_db_list),ok_count+er_count, ok_count, er_count))
        
    
    return ws

def analyze_workers(ws, write_output=True):
    
    # do basic chain distribution
    ws.analyze()
    
    # analyze if logon events are handled in time (against called)
    ws.analyzer.analyze_chain_called()

    # analyze NTLM messages
    ws.analyzer.analyze_chain_ntlm_seq()

    # DEBUG: wow, dump whole chain database
    # ws.analyzer.print_chain()
    
    if write_output:
        f = open_file(ws.ca_log,"ANALYZER")
        if f:
            nl = ws.write_tasks(f,ws.analyzer.anno_db["severity"])
            f.close()
            logger_analyzer.info("%d non-empty lines written to the file" % (nl,))


def open_file(fnm,suffix=None):
    
    s = "PRGERROR"
    if suffix: s = suffix
        
    norm = os.path.normpath(fnm)
    d = os.path.dirname(norm)
    f = os.path.basename(norm).split()[0]
    target = os.path.join(d,f + "." + s + ".log")
    logger_state.info("["+ suffix +"] filling the file: %s" % (target,))

    f = None
    try:
        f = open(target,"w+")
        logger_state.debug("Sucessfully opened/truncated file '%s'" % (target,))
    except Exception, e:
        logger_state.critical("Unable to open/truncate the worker log file! Please check and re-run me. Current outputs are inconsistent. Bailing out due '%s'!" % (str(e),))
    
    return f

def search_workers(ws,srch_string_list,srch_string_list_neg=None,prefix_lines=True):
    logger_state.info("Line search:")
    logger_analyzer.debug("search_workers: searching positive ALL %s, negative ANY %s" % (str(srch_string_list),str(srch_string_list_neg)))
    ws.search_line(srch_string_list,srch_string_list_neg)

    r = False
        
    f = open_file(ws.ca_log,"SEARCH")
    if f:
        nl = ws.write_tasks(f,{ "line search: %s/%s" % (str(srch_string_list),str(srch_string_list_neg)) : ws.search_line_result() })
        f.close()
        logger_analyzer.info("%d non-empty lines written to the file" % (nl,))
        r = True
    
    logger_state.info("done!")
    return r


    

"""
FIXME: some sane description
"""            
def split_workers(ws,calog_fnm,method,prefix_lines=True,task_separator=True):

    logger_state.info("Splitting by %s:" % (method,))

    if method == 'none':
        logger_state.info("Splitting skipped, per your request.")
        return

    opened_files = {}

    dot_counter = time.time()
    tasks_written = 0
    logger_state.info("About to write %d tasks" % (len(ws.task_db_list),))
    
    for t_id in ws.task_db_list:
        
        # because we are appeding gids (t_id here) immediatelly as they appear in the log,
        # we are not sure if the db was filled
        if t_id not in ws.task_db.keys():
            continue
    
        logger_state.debug("Processing task: %s, role=%s" % (t_id,ws.task_db[t_id]['role']))
       
        norm = os.path.normpath(calog_fnm)
        d = os.path.dirname(norm)
        f = os.path.basename(norm).split()[0]
        
        pid, sub_pid, id = t_id.split('-')
        
        target = os.path.join(d,f + ".DEFAULT.log")
        
        if method == "workers":
            target = os.path.join(d,f + "." + ws.task_db[t_id]['role'] + "_" + pid + ".log")
        elif method == "role":
            target = os.path.join(d,f + "." + ws.task_db[t_id]['role'] + "_all.log")
        elif method == "reorder":
            target = os.path.join(d,f + ".reordered.log")
       
        if ws.task_db[t_id]['role'] == Worker.ROLE_UNKNOWN:
            target = os.path.join(d,f + "." + "UNRECOGNIZED_" + method + ".log")
        
        if target not in opened_files.keys():
            logger_state.info("[SPLIT] filling the file: %s" % (target,))
            
            try:
                opened_files[target] = open(target,"w+")
                logger_state.debug("[SPLIT] Sucessfully opened/truncated file '%s'" % (target,))
            except Exception, e:
                logger_state.critical("[SPLIT] Unable to open/truncate the worker log file! Please check and re-run me. Current outputs are inconsistent. Bailing out due '%s'!" % (str(e),))
                system.exit(-66)
        
        for l in ws.task_db[t_id]['log']:
            l_w = l + "\n"
            if prefix_lines: l_w = t_id + " " + l + "\n"
            
            logger_state.debug("[SPLIT] writing in the file: '%s' line: '%s'" % (target,l_w))
            opened_files[target].write(l_w)

        if "anno" in ws.task_db[t_id].keys():
            for a in ws.task_db[t_id]["anno"]:
                l_w = Analyzer.annotate_format(a) + '\n'

                logger_state.debug("write_task: annotation line to write: '%s'" % (l_w,))
                opened_files[target].write(l_w)        
        
        if task_separator:
            opened_files[target].write("\n\n")

        
        tasks_written+=1
        if time.time() - dot_counter > 10:
            perc = 100*tasks_written/len(ws.task_db_list);
            logger_state.info('%d tasks written ... (%2.1f%%)' % (tasks_written,perc,))
            dot_counter = time.time()
        
            
    for f in opened_files.keys():
        try:
            opened_files[f].close()
        except Exception,e:
            logger_state.critical("Unable to close file '%s': %s" % (f,str(e)))

    logger_state.info("done!")




            
def parse_args():
    parser = argparse.ArgumentParser(description='CANASTA: CA log aNAlyzer by ASTibAl.\nThe intention was to help you troubleshoot CA logs and FSSO issues.',
                                     epilog="""Created by Ales Stibal <astibal@fortinet.com>, L2 TAC Prague, Fortinet """)
    parser.add_argument('-cl','--calog', dest='calog',default='CollectorAgent.log',
                       help='collector agent log file (default: CollectorAgent.log)')

    parser.add_argument('-i','--interactive', dest='interact',default=False,help="Load the file and run into interactive mode",const=True,nargs='?')

    parser.add_argument('--no-prefixes',dest='no_prefixes',default=False,help="While processing, each line is prefixed with it's task id. This command will avoid this.", const=True, nargs='?')
    
    parser.add_argument('-sb','--split-by', dest='split_by',default="none", choices=['none','workers','role','reorder'], 
        help="STATE: Split the log into separate files. Criteria: none, workers, role, reorder. Default: %(default)s",const="worker",nargs='?')
    parser.add_argument('-an','--analyze',dest='analyze',default=False,help="DEV: Go through the tasks and analyze the log. Under development!", const=True, nargs='?')
    parser.add_argument('-ls','--llsearch', dest='search', action="append", help='Line-level search: write to file all tasks where any line is matching this argument (currrently only regular expression is supported).')
    parser.add_argument('-lsn','--llsearch-neg', dest='search_neg', action="append", help='Line-level search: task match is canceled if any of this expressions are matched.')
    
    parser.add_argument('-chs','--chsearch', dest='chsearch', action="append", help='Chain-level search: write to file all tasks where chain is matched by regex. Form: --chsearch ip:<opt_type>:"<my-regexp>"')
    parser.add_argument('-cho','--chout', dest='chout', action="append", help='Chain-level search: modify filename suffix, instead of <filename>.CHAIN.log write to <filename>.CHAIN.<suffix>"')
    
    parser.add_argument('--debug-state', dest='debug_state',default=20,help='State machine verbosity: 50=critical, 40=errror, 30=warning, 20=information, 10=debug',const=10,nargs='?')
    parser.add_argument('--debug-analyzer', dest='debug_analyzer',default=20,help='Analyzer verbosity: 50=critical, 40=errror, 30=warning, 20=information, 10=debug',const=10,nargs='?')
    parser.add_argument('--debug-data', dest='debug_data',default=0,help='Dump data converted to JSON structures into a file',const=10,nargs='?')

    parser.add_argument('-m','--man',dest='manpage',default=False,help="Display verbose man page", const=True, nargs='?')
    parser.add_argument('-V','--version',dest='version',default=False,help="Display version and quit", const=True, nargs='?')
    args = parser.parse_args()
    return parser,args



man_main = """

--== CANASTA tool by Ales Stibal, Fortinet L3 TAC in Prague ==--  


CANASTA is the tool to make your Collector Agent issues analysis easier.
Canasta parses FSSO Collector Agent log and packs events from it into so
called "tasks". This is very useful on its own.

Additionally, based on those "tasks", it is able to warn you about noticeworthy 
details which could be easily overlooked.

All results are chronologically ordered. The ordering is based on timestamp 
when the task started.


--== HOW IT WQRKS ==--

1. Separation to the tasks
======================================
The lines are matched against certain set of regular expresions. We are looking 
basically for patterns which divide log into self-contained tasks, for example 
logon event of some user, or IP check on single workstation name.

At this moment, you can direct canasta script to save those tasks and lines, 
depending on which point of view you are interested in:
 
 --split-by reorder :  This will save all tasks chronologically into SINGLE file, 
                       ordered by task creation timestamp.
                       Result is almost the same as the original CollectorAgent.log, 
                       but instead of mess of unrelated lines you have list
                       of tasks packed together.
                       
                       By far the most useful split method.
                       
                       Output filename is: CollectorAgent.log.reordered.log

 --split-by worker  :  sometimes, you need to study output of one particular 
                       thread. This option will create files for each worker, 
                       indicating also the worker role.
                       
                       Filename is like: CollectorAgent.log.logons-msg_12312.log
                       so it's following the pattern:
                                       CollectorAgent.log.<role>_<worker_id>.log
                                         
 --split-by role    :  This option allows all tasks of particular role to be put
                       in the particular file, regardless of thread id. 
                       
                       Filename is like: CollectorAgent.log.logons-msg_all.log.
                                         
                            ... so the thread id is replaced by all, and all 
                            tasks with this role are put to that single file.
                            

--split-by none     :  use this option if you aren't looking for task separation 
                       at all. Probably you want Canasta to do heurstics
                       only, so splitting the lines into files is not needed.
                           
 --no-prefixes      :  In all cases the output file lines  are prepended  by 
                       TASK ID. This task id consists of tuple of decimal numbers 
                       separated by hyphen, e.g. 12312-0-34. 
                       This means the thread id is 12312, and the line belongs 
                       to 34th  task processed by  the thread. Zero in the 
                       middle is ID of tge sub-parser. Good example of 
                       sub-parser is event poller parser.
                       
                       For those who don't want to  have task-id at the every 
                       beginning of the line in files, please use this option. 
                       This will also prevent Canasta to separate tasks by two 
                       empty lines.
                       
                       
2. Line-level search
====================
Regarless you have used --split-by feature, you have the possibility to perform
                       case-ignoring regex search in all detected tasks:

 --llsearch <regexp>:  Use regular expression to match each line in each task. 
                       If at least single task line matches your regexp, this whole 
                       task is matching. 
                       Matching tasks are saved into CollectorAgent.log.SEARCH.log
                       file. It is always rewritten and is NOT named by your 
                       regexp, as it can be quite complex.
                       
                       You can use this option several times. Do so if you want 
                       the task to match ALL of them (it doesn't matter where 
                       in the task).
                       
                       You can use  eg. --llsearch 'foo' --llsearch 'that' \\
                                --llsearch 'bars'.

                       
 --llsearch-neg <neg_regexp>:
                       If this option is used, any line in the task must not 
                       match this regexp, regardless what --llsearch result is.
                       Matching this regular expression prevents the task to
                       be finally positively matched.
                       
                       This option could be used several times too. Task
                       matches ANY of --llsearch-neg expressions is prevented 
                       to be finally matched.
                                   
                       
 3 Chain-level search
 ====================
 
 Chain level search is performed on the list of tasks and is independent on --llsearch
 options (they cannot be used concurently). 
 This search is aware of what log lines belonging to the task mean. Thus it is 
 able to interpret some messages and it content as IP address, usernames, workstations,
 etc.
 This information is saved into internal database I call "chains", since it contains
 lists of related events, based on metadata value. For example, there is a chain
 of events related to the workstation ABC.
 You can use --chsearch option to search for such a chain, based on its type and value.
 
 You can search it as follows:
 
 --chsearch <keyword>:<match_type>:<expression>
               keyword: which relation line you are looking for? 
                        ip       - ip1 or ip2 (see bellow)
                        wksta    - workstation name 
                        user     - username 
                        domain   - domain of the user
                        ip1      - primary ip address reported by dcagent
                        ip2      - secondaty ip address reported by dcagent
                        called   - logon even id : displays only messages of 
                                   dcagent-io-recv and logons-msg 
                                   workers. (see worker role)
                        ntlm_seq - NTLM sequential number as it comes from 
                                   Fortigate
            
            expression: pattern used for matching the keyword value. No default.
            
            match_type: how the expression should be matched against the keyword 
                        value? 
                        rxi    - regular expression, ignoring cAsE
                        exi    - exact match, but ignoring CaSe
                        
                        ip     - will try to match the pattern as IP address,
                                 with fallback to 'exi'
                        
                        Default is 'rxi', so if you ommit this parameter, 'rxi'
                        will be used.
            
            For the safer usage use apostrophes for the <expression> instead of 
                        quotes.
            
            EXAMPLE 1 (regex ignoring cases):
               --chsearch wksta::'PC[0-1]+.lab.net'
               
            EXAMPLE 2 (ip, treating as IP):
               --chsearch ip:ip:'10.31.8.0/24'
 
            All matching tasks are saved in the file CollectorAgent.log.CHAIN.log.
            
 
 4. Interactive mode [under development]
 Are you doing some more complex research with large data? Then parsing all files
 over again is tedious. There was an intention to save "cache" data file with
 result of parsing, however, loading this file would take similar time compared to
 parse it again.
 Interactive mode paritally solves this problem, since it loads data just once. 
 It's up to you what you will really do with them. Commands are very similar as the
 arguments of canasta itself. Please take a look on 'help' command.
 
 Interactive mode is activated with --interactive, or -i option.
                       
 BUGS AND LIMITATIONS:
 =====================
 - Canasta can process only the DEBUG LEVEL logs. Other will show only incomplete
   and not reliable results.
 - Analyzer is still in development
"""

version="""
    
CANASTA %s, tool for Fortinet Collector Agent troubleshooting.
Written by Ales Stibal <astibal@fortinet.com>, Fortinet, L2 TAC Prague (c) 2013    
""" % __version__

def print_man(arg_parser,args):
    print man_main
    

class CanastaShell(cmd.Cmd):
    def __init__(self,args):
        cmd.Cmd.__init__(self)
        self.prompt = 'canasta> '
        self.workers_ = None
        self.args = args
    
    def set_workers(self,w):
        self.workers_ = w
    
    def get_workers(self):
        return self.workers_
    
    def do_analyze(self,arg):
        logger_state.info("Analyzing:" )
        analyze_workers(self.workers_,write_output=(self.args.split_by == 'none'))
        logger_state.info("done!")          

    def do_test(self,arg):
        logger_state.info(pformat(arg))
    
    def do_chsearch(self,arg,suf=None):
        logger_state.info("Chain search:" )
        
        i_var = arg
        if type(arg) != type([]):
            i_var = [arg,]
            
        self.get_workers().chsearch_suffix = suf
        self.get_workers().search_chain(i_var)        
        
        logger_state.info("done!")         
    
def main():
    arg_parser,args = parse_args()
    sh = CanastaShell(args)    
    
    if len(sys.argv) == 1:
        arg_parser.print_help()
        sys.exit(-1)
    
    if args.manpage:
        print_man(arg_parser,args)
        sys.exit(-1)

    if args.version:
        print version
        sys.exit(-1)

    if not os.path.exists(args.calog):
        logger_state.critical("File '%s' is not readable, or does not exist!" % (args.calog,))
        sys.exit(-1)

    # init the logging 
    logger_state.setLevel(int(args.debug_state))
    logger_analyzer.setLevel(int(args.debug_analyzer))
    logger_state.debug("loglevel set to: %d" % (int(args.debug_state),))    
    logger_analyzer.debug("loglevel set to: %d" % (int(args.debug_analyzer),))


    # Process errors in used options
    
    # we don't support commbined chsearch with llsearch!
    if args.chsearch and args.search:
        logger_state.error("Combination of chain search and line-level search is not supported.")
        logger_state.error("Contact sales@fortinet.com for a NFR ;-)")
        return    
    
    # Do the task used in all cases:
    start = time.time()

    ws = proc_calog(args.calog)       
    sh.set_workers(ws)

    # fill the condition with anything which will utilize analyzer engine
    # make it before anything else, so outputs can benefit from having analysis done already
    if args.analyze or args.chsearch or args.chsearch or args.interact:
        sh.do_analyze(None)    

    if args.chsearch:
        suf = None
        if args.chout:
             # merge them all into dotted separate single suffix
             suf = ".".join(args.chout)
             
        sh.do_chsearch(args.chsearch,suf)
        
    if args.search or args.search_neg:
        # if only negative search is present, set positive to match all lines
        if not args.search: args.search=['.*',]
        search_workers(ws,args.search,args.search_neg,not args.no_prefixes)

    
    if args.split_by != 'none':
        split_workers(ws,args.calog,args.split_by, not args.no_prefixes)
    
    if args.interact:
        logger_state.info("Entering interactive mode")
        logger_state.info("... you don't have to use quotes and apostrophes in command arguments")
        logger_state.info("")
        sh.cmdloop()
        return
        
    t = time.time() - start
    logger_state.info("Processing finished in %.2f secs!" % (t,))

    
    if int(args.debug_data):
        fnm = args.calog + '.json'
        logger_state.info("JSON dump to '%s'!" % (fnm,))
        f = open(fnm,'w+')
        
        dump = {}
        dump["workers"] = ws.data()
        dump["analyzer"] = ws.analyzer.data()
        json.dump(dump,f,indent=4)
        f.close()
        logger_state.info("done!")




try:        
    #import cProfile
    
    #cProfile.run(main())
    main()
except KeyboardInterrupt, e:
    logger_state.error("Interrupted!")
    
    
    


# FIXME: various log lines, which need to be synthetized:

# WORKER SENDING LOGON EVENTS TO FORTIGATE is also saving cache to files
# 
# logon cache saved to file: C:\Program Files (x86)\Fortinet\FSAE\LogonCache.dat
# group cache (815) saved to file: C:\Program Files (x86)\Fortinet\FSAE\GroupCache.dat
# COLLEGE\ZAHEERAB:CN=ZAHEERAB,OU=Staff,OU=Users,OU=TCD,DC=college,DC=tcd,DC=ie+CN=Domain Users,CN=Users,DC
# =college,DC=tcd,DC=ie+CN=Staff,OU=Global Groups,DC=college,DC=tcd,DC=ie+CN=D404,OU=Global Groups,DC=college,DC=tcd,DC=ie+CN=Staff-OU,
# OU=Global Groups,DC=college,DC=tcd,DC=ie+CN=Exch-Group,OU=Global Groups,DC=college,DC=tcd,DC=ie+CN=Users,CN=Builtin,DC=college,DC=tcd
# ,DC=ie+CN=proxywww,OU=Global Groups,DC=college,DC=tcd,DC=ie
# check_config_change() called
