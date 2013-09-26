#!/usr/bin/env python
"""
   Canasta - Collector log Analyzer by Ales Stibal
   Copyright: Ales Stibal, astibal@fortinet.com, Fortinet L2 TAC (c) 2013
   
   Disclaimer: Program has been written during the nights and exclusively in my spare time.  
               The program is dedicated to my beloved Kate and my awesome sons Vojtech and Filip.
               And also to all FSSO freaks working in Fortinet, of course!
   
   License: BSD original license
"""

__version__="0.1.4-1"

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

from pprint import pprint
from pprint import pformat

import ipaddr

line_start=r'(?P<timestamp>\d\d/\d\d/\d\d\d\d \d\d:\d\d:\d\d) +\[ *(?P<pid>\d+)\] +'

# ip check
func_update_entry_ip=r'(?P<function>update entry)\((?P<param>[\w ]+)\): +ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) +create time:(?P<create_time>\d+) +update time:(?P<update_time>\d+) +ip update time:(?P<ip_update_time>\d+) +workstation:(?P<wksta>[\w_.\-]+) +domain:(?P<domain>[\w_.-]+) +user:(?P<user>[\w_.-]+) +group:(?P<group>[\w_.,+=& \-]+)'
func_resolve_ip_internal=r'(?P<function>resolve_ip_internal): +workstation:(?P<fqdn>[\w.]+) +\[(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\] +time:(?P<duration>\d+)'
func_after_dns_checking=r'after (?P<function>DNS_checking):(?P<wksta>[\w.]+)'
func_before_dns_checking=r'before (?P<function>DNS_checking):(?P<wksta>[\w.]+)'
func_dns_query_valid=r'(?P<function>DnsQuery)\(\): (?P<status>[^:]+): +ip:(?P<ip_hex>[\da-fA-F]+)'

# wksta_check
func_update_entry_workstation=r'(?P<function>update entry)\((?P<param>[\w ]+)\): +ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) +create time:(?P<create_time>\d+) +update time:(?P<update_time>\d+) +workstation:(?P<wksta>[\w_.\-]+) +domain:(?P<domain>[\w_.-]+) +user:(?P<user>[\w_.-]+) +group:(?P<group>[\w_.,+=& \-]+)'
func_wksta_verify_ip=r'verify_ip: workstation:(?P<wksta>[\w._-]+) \[(?P<ip1>[\d.]+):(?P<ip2>[\d.]+)\] time:(?P<time>\d+)'
func_wksta_test=r'user:(?P<user>\w+) on domain:(?P<domain>\w+) sid:(?P<sid>[\w-]+)'
func_wksta_registry_error=r'cannot access registry keys:(?P<err_code>\w+)'
func_wksta_still=r'wksta_check: user:(?P<domain>[^\\]+)\\(?P<user>\w+) is still logged on to (?P<wksta>[\w-_.]+)'
func_wksta_no_longer=r'wksta_check: user:(?P<domain>[^\\]+)\\(?P<user>\w+) is no longer logged on to (?P<wksta>[\w-_.]+) \((?P<ip1>[\d.]+)\)'

# DC Agent processing workers
func_process_dcagent_events=r'process_dcagent_events called by worker:(?P<caller_pid>[\d]+)'
func_dcadgent_remove_q='dcagent packet: removed from queue, called:(?P<called>\d+) remain:(?P<remain>\d+)'
#                       NTLM packet: removed from queue, called:31770355 remain:0
func_ntlm_remove_q='NTLM packet: removed from queue, called:(?P<called>\d+) remain:(?P<remain>\d+)'
func_logon_event=r'logon event\((?P<called_id>\d+)\): len:(?P<length>\d+) dc_ip:(?P<dc_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) time:(?P<dc_timestamp>\d+) len:\d+ data:(?P<wksta>[\w\d.]+)/(?P<domain>\w+)/(?P<user>[\w ]+) ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
func_logon_event_ex=r'logon event\((?P<called_id>\d+)\): len:(?P<length>\d+) dc_ip:(?P<dc_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) time:(?P<dc_timestamp>\d+) len:\d+ data:(?P<wksta>[\w\d.]+)/(?P<domain>\w+)/(?P<user>[\w ]+) ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
func_new_logon_0=r'(?P<function>new logon), +workstation:(?P<wksta>[\w.]+) +ip:(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
func_new_logon_1=r'(?P<function>new logon), +workstation:(?P<wksta>[\w.]+) +ip not changed +(?P<ip1>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<ip2>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
func_ntlm_user=r'user:(?P<user>\w+)'
func_ntlm_domain=r'domain:(?P<domain>[\w._-]+)'
func_ntlm_wksta=r'workstation:(?P<wksta>[\w._-]+)'


# Fortigate receive IO workers (FIXME)
func_fortigate_io_recv=r'Bytes received from FortiGate: (?P<bytes>\d+)'

# Fortigate send IO workers (FIXME)
func_fortigate_io_send=r'get record from send queue: sock:(?P<fdr>[\da-fA-F]+):(?P<fdw>[\da-fA-F]+) buffer:(?P<ptr>[\da-fA-F]+) len:(?P<data_length>\d+) queue size:(?P<queue_length>\d+)'

# Fortigate messaging worker (FIXME)
func_fortigate_msg_fgt_connected=r'(?P<count>[\d]+) FortiGates{0,1} connected'
func_fortigate_msg_cache_logon_send=r'check the cache to send logon events'
func_fortigate_msg_cache_logon_user=r'not in filter: last user:(?P<user1>[^ ]+) user:(?P<user2>[^ ]+)'
# group list unreliable, truncated at 900th character
func_fortigate_msg_cache_logon_group=r'not in filter: last user:(?P<group1>[^ ]+) user:(?P<group2>[^ ]+)'

func_fortigate_msg_cache_logoff_purge=r'check the cache to purge logoff entries'
func_fortigate_msg_cache_logoff_user=r'(?P<wksta>[\w._-]+):(?P<user>\w+)\[(?P<ip1>[\d.]+):(?P<ip2>[\d.]+)\] removed. current time:(?P<current_time>\d+) last update time:(?P<update_time>\d+) age:(?P<age>\d+)'

func_fortigate_msg_cache_user_saved=r'logon cache saved to file'
func_fortigate_msg_cache_group_saved=r'group cache \(\d+\) saved to file'


# DC Agent messaging worker
func_dcagent_msg_received=r'Bytes received from DC agent\((?P<called>\d+)\): (?P<msg_bytes>\d+) dcagent IP: (?P<ip_hex>[\da-fA-F]+), MT=(?P<mt>\d+)'

# Group checking, while updating IP (done by different thread)
func_update_groupcheck=r'check the entry to see if the user\'s group info changed' # yes, no info inside!

# Main thread which is accepting TCP sessions from Fortigates
func_fortigate_io_accepted=r'accepting one FortiGate connection'

# poller thread (FIXME)
# ... this time it's being ignored
# func_poller_debug_dcpoller=r'\[D\]\[DCPoller\].*'
# func_poller_arrows=r'\[I\]\[[LD][SC]Poller\][^>]+>$'

func_poller_dopoll=r'\[I\]\[LSPoller\]DoPolling\(ip=(?P<ip>[\d\w]+), host=(?P<fqdn>[\w\d./]+)\): r=(?P<r>\d+)'
#func_poller_nsenum=r'[I][DCPoller]NSEnum([\w\d.]): r=\d+, e=\d+, R=\d+, T=\d+, H=0x[\da-fA-F]+'


"""
 GLOBAL LOGGING SETUP
"""
logger_state = logging.getLogger("state")
logger_analyzer = logging.getLogger("analyzer")

ch = logging.StreamHandler()
formatter = logging.Formatter('[%(levelname)s][%(name)s] %(message)s')
ch.setFormatter(formatter)

logger_state.addHandler(ch)
logger_state.setLevel(logging.DEBUG)
logger_analyzer.addHandler(ch)
logger_analyzer.setLevel(logging.DEBUG)

    
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

    def __init__(self,pid,workerset):
        self.pid = pid
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
        
        # map of regular expressions idicating new cycle/state to roles
        self.new_state_events = {}
        # replace with removal event from queue -- this relpaced log line will be ignored, since we need  to hit all logon events, not just 
        # the first when the logons are removed from queue by more than one
        # ... and func_process_dcagent_events does not have much informational value anyway
        
        #self.new_state_events[line_start+func_process_dcagent_events] = Worker.ROLE_LOGONS
        self.new_state_events[line_start+func_dcadgent_remove_q] = Worker.ROLE_LOGONS
        self.new_state_events[line_start+func_ntlm_remove_q] = Worker.ROLE_LOGONS
        self.new_state_events[line_start+func_update_entry_ip] = Worker.ROLE_UPDATERIP
        self.new_state_events[line_start+func_update_entry_workstation] = Worker.ROLE_UPDATERWKS
        self.new_state_events[line_start+func_fortigate_io_recv] = Worker.ROLE_FGTIORECV
        self.new_state_events[line_start+func_fortigate_io_send] = Worker.ROLE_FGTIOSEND
        # removed on 0.1.1a -- seems to be right decision
        #self.new_state_events[line_start+func_fortigate_msg_fgt_connected] = Worker.ROLE_FGTMSG
        self.new_state_events[line_start+func_fortigate_msg_cache_logon_send] = Worker.ROLE_FGTMSG
        self.new_state_events[line_start+func_fortigate_msg_cache_logoff_purge] = Worker.ROLE_FGTMSG
        self.new_state_events[line_start+func_fortigate_msg_cache_user_saved] = Worker.ROLE_FGTMSG
        self.new_state_events[line_start+func_fortigate_msg_cache_group_saved] = Worker.ROLE_FGTMSG
        
        self.new_state_events[line_start+func_dcagent_msg_received] = Worker.ROLE_DCAGENTIORECV
        self.new_state_events[line_start+func_update_groupcheck] = Worker.ROLE_UPDATERGROUP
        self.new_state_events[line_start+func_fortigate_io_accepted] = Worker.ROLE_FGTIOMUX
        self.new_state_events[line_start+func_poller_dopoll] = Worker.ROLE_DOPOLL

        # ignored lines, which are duplicating info, or just unecessarily screw up parsing :)
        #self.new_state_events[line_start+func_poller_debug_dcpoller] = Worker.ROLE_IGNORED
        #self.new_state_events[line_start+func_process_dcagent_events] = Worker.ROLE_IGNORED
        
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
        self.poller_log.append(line.strip())
    
    """
    update: let update worker with line from the log. 
    @return: None if no task is completed or task_data if the task is finished with this line
    """     
    def update(self, line):
        
        if re.search('\[[DL][CS]Poller\]',line):
            self.update_poller(line)
            return None
    
        self.log.append(line.strip())
        current_index = len(self.log)-1
        #logger_state.debug(" ... current index:" + str(current_index))
        
        m = None
        m_r = Worker.ROLE_UNKNOWN
        
        for n in self.new_state_events:
            m = re.match(n,line) 
            if m:
                # set match role according new_state_event dictionary
                m_r = self.new_state_events[n]
                
                logger_state.debug("Worker "+ self.pid + ": new state: " + m_r + " : " + line)
                if m_r == Worker.ROLE_IGNORED:
                    return None
                break
            
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
        task_data['role'] = self.state_role
        task_data['data'] = self.state_data
        task_data['id'] = len(self.task_list)
        task_data['gid'] = "%s-%s" % (task_data['pid'],task_data['id'])
        task_data['log'] = []
        for li in range(self.state_index_a,len(self.log)-1):
            logger_state.debug("+++ " + self.log[li])
            task_data['log'].append(self.log[li])
        
        self.task_list.append(task_data)
        self.parent.finish_task(task_data)
        logger_state.debug("+++ ... task completed: id=%d, lines=%d, line index=(%d,%d)" % 
                (task_data['id'],len(task_data['log']),self.state_index_a,len(self.log)-1))

      

class Workers:
    """
     Workers: log entry dispatcher
     each log line is analyzed and according to pre-matched PID is distributed to it's corresponding
     worker object.
    """
    
    def __init__(self,ca_log):
    
        self.ca_log = ca_log
        self._workers = {}
        self.analyzer = Analyzer(self)
        
        # chrono list of tasks finished by workers
        self.task_chain = []
        # pid-id dict of tasks
        self.task_db = {}
        self.task_db_list = []
    
    
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
        t_id_this = "%s-%s" % (task_data['pid'],task_data['id'])
        self.task_db[t_id_this] = task_data
        
        
        # because we finish the task when the new one is recognized
        t_id_next = "%s-%s" % (task_data['pid'],task_data['id']+1)
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

        #pprint(r)

        # this will normalize someday: currently only PER chain lists will be 
        # ordered chronologically
        norm = {}

        for ch in r.keys():
            j = -1
            for i in r[ch]:
                j += 1
                for ch_n in i.keys():
                    norm["%s : %s[%d]" % (ch,ch_n,j)] = r[ch][j][ch_n]

        f = open_file(self.ca_log,"CHAIN")
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
        m = re.match(line_start,line)
        
        if m:
            #logger_state.info("processing: " + line)
            return self._update_worker(m.group('pid'),line)
            
        else:
            if not line:
                logger_state.debug("ignoring blank line")
            else:
                logger_state.debug("ignoring non-conforming line: '%s'" % (line,))
        
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
            logger_state.info('write_task: dumping whole database')
            ts = {"database dump": self.task_db_list}
        
        for ts_l in ts.keys():
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
                        lines_written += 1
                    if prefix_lines:
                        f.write("\n\n")
                        
        return lines_written


class Analyzer:
    
    DEBUG_MATCH = 0
    
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
        # example: self.chain['called']['44432-1'] = [... list of relevant task gids ...]
        
        # non-virtual (real) keys present in the regex groups. You can add virtual ones later by mapping
        self.chain_keys = ['called','ip1','ip2','wksta','domain','user'] 
        for _k in self.chain_keys:
            self.chain[_k] = {}
    
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
                sys.exit(-1)
                
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
                        m = ( ex == k.lower())
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
                            logger_analyzer.info("[D] partial match: ('%s' matches '%s' expression '%s')" % (k,typ,ex))
                        else:
                            # strategy=="ANY"
                            logger_analyzer.info("[D] sufficient match: ('%s' matches '%s' expression '%s')" % (k,typ,ex))
                            matches_this_criteria = True
                            break
                    else:
                        matches_this_criteria = False
                        

                if matches_this_criteria and cur:
                    # all of the same criteria key matched
                    logger_analyzer.info("[D] complete match: %s" % (cur,))
                    matches = Analyzer.stack_dict(matches, { c:{ cur: self.chain[c][cur] }})

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
                m = re.search(s,l)
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
        if task_data['role']==Worker.ROLE_DCAGENTIORECV:
            logger_analyzer.debug('analyzing msg from dcagent: taskid=%s' % (task_data['id'],))
            result = self.analyze_dcagent_msg(task_data)
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
        else:
            pass
            #logger_analyzer.error('Unknown task role: %s' % (task_data['role'],))
    
    def analyze_dcagent_msg(self, task_data):
        """
        Analyzing and chaining the messages of DCAgent 
        """
        
        gid = task_data['gid']
        result = {}
        result['gid'] = gid
    
        for l in task_data['log']:
            m = re.match(line_start+func_dcagent_msg_received,l)
            if m:
                c = m.group('called')
                logger_analyzer.debug("analyze_dcagent_msg: matched msg_received")
                if c in self.chain['called'].keys():
                    logger_analyzer.debug('analyze_dcagent_msg: called ID %s alrady processed! Skipping.' % (c,))
                    continue
                
                #result['called'] = c
                result = Analyzer.stack_dict(result,{'called':c})

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
                  
            # match the very first meaningfull log line
            # e.g.
            # dcagent packet: removed from queue, called:1428633 remain:0
            m = re.match(line_start+func_dcadgent_remove_q,l)
            if m:
                c = m.group('called')
                if c not in self.chain['called'].keys():
                    logger_analyzer.debug("analyze_logons: called ID '%s' not found! Skipping." % (c,))
                    # FIXME: this could be handled more elegant way: the logon event which cannot be paired 
                    # will be marked as <incomplete>
                    continue
                if 'called' not in result: result = Analyzer.stack_dict( result, {'called':c})
                continue

            
            m = re.match(line_start+func_ntlm_remove_q,l)
            if m:
                
                LOGON_NTLM = True
                
                c = m.group('called')
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
            m = re.match(line_start+func_logon_event_ex,l)
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
            m = re.match(line_start+func_logon_event,l)
            if m:
                # update the result dict by the match
                logger_analyzer.debug("analyze_logons: func_logon_event: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue
           
            # 
            m = re.match(line_start+func_new_logon_0,l)
            if m:
                # update the result dict by the match
                logger_analyzer.debug("analyze_logons: func_new_logon_0: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue     
                
            m = re.match(line_start+func_new_logon_1,l)
            if m:
                # update the result dict by the match
                logger_analyzer.debug("analyze_logons: func_new_logon_1: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue         
                

            # ANALYZE NTLM LOGON EVENT
            if LOGON_NTLM:
                m = re.match(line_start+func_ntlm_user,l)    
                if m:
                    # update the result dict by the match
                    logger_analyzer.debug("analyze_logons: func_nlm_user: %s" % (l,))
                    #result.update(m.groupdict())
                    result = Analyzer.stack_dict(result,m.groupdict())
                    continue         

                m = re.match(line_start+func_ntlm_wksta,l)    
                if m:
                    # update the result dict by the match
                    logger_analyzer.debug("analyze_logons: func_nlm_wksta: %s" % (l,))
                    #result.update(m.groupdict())
                    result = Analyzer.stack_dict(result,m.groupdict())
                    continue         

                m = re.match(line_start+func_ntlm_domain,l)    
                if m:
                    # update the result dict by the match
                    logger_analyzer.debug("analyze_logons: func_nlm_domain: %s" % (l,))
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
            m = re.match(line_start+func_update_entry_workstation, l)
            if m:
                logger_analyzer.debug("analyze_wksta_check: func_update_entry_workstation: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue
            
            m = re.match(line_start+func_wksta_verify_ip, l)
            if m:
                logger_analyzer.debug("analyze_wksta_check: func_wksta_verify_ip: %s" % (l,))
                #result.update(m.groupdict())
                result = Analyzer.stack_dict(result,m.groupdict())
                continue
         
            # important thing is revealed: SID
            m = re.match(line_start+func_wksta_test, l)
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
            m = re.match(line_start+func_fortigate_msg_cache_logon_send, l)
            if m:
                logger_analyzer.debug("analyze_fortigate_msg: func_fortigate_msg_cache_logon_send: %s" % (l,))
                continue
                
            m = re.match(line_start+func_fortigate_msg_cache_logoff_purge, l)
            if m:
                logger_analyzer.debug("analyze_fortigate_msg: func_fortigate_msg_cache_logoff_purge: %s" % (l,))
                continue
            
            m = re.match(line_start+func_fortigate_msg_cache_logon_user, l)
            if m:
                logger_analyzer.debug("analyze_fortigate_msg: func_fortigate_msg_cache_logon_user: %s" % (l,))
                user1 = m.group('user1')
                user2 = m.group('user2')
                logon_users.append(user2)
                logoff_users.append(user1)
                result = Analyzer.stack_dict(result,{'user': [user1,user2]})
                continue
                
            m = re.match(line_start+func_fortigate_msg_cache_logoff_user, l)
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
            m = re.match(line_start+func_update_entry_ip, l)
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

                    # update the chain with task GID -- this GID contains reference to the keyword!
                    self.chain[ch][c_i].append(result_struct['gid'])
                
                
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

                        self.chain[virtual_map[ch]][c_i].append(result_struct['gid'])
                    
            else:
                logger_analyzer.debug("regex group '%s' not present in the task '%s'" 
                        % (ch,result_struct['gid']))
                    
    
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
        
        if m1 and m2:
            delta = Analyzer.strptime(m2.group('timestamp')) -  Analyzer.strptime(m1.group('timestamp'))
            
            # DEP: 2.7
            return delta.total_seconds()

        return None
    
    
    @staticmethod
    def task_delay(t1, t2):
        return Analyzer.line_timedelta(t1['log'][-1],t2['log'][0])
        
    
    @staticmethod
    def chain_delays(task_list):
        l = len(task_list)
        r = []
        for x in xrange(0,l-1):
            r.append( Analyzer.task_delay(task_list[x], Analyzer.task_list[x+1]))
        
        return r
        
    def analyze_called(self):
        logger_analyzer.debug("[ANAL]... processing 'called' chain: start")
        
        for c in self.chain['called']:
            logger_analyzer.debug("[ANAL]... processing 'called' ID: %s" % (c,))

            # FIXME: testing ... just length of 2 is processed, others silently ignored
            if len(self.chain['called'][c]) == 2:
                t1 = self.chain['called'][c][0]
                t2 = self.chain['called'][c][1]
                d =  Analyzer.task_delay(self.workers.task_db[t1],self.workers.task_db[t2])
                
                if d > 120:
                    logger_analyzer.critical("[ANAL]... huge delay in processing %s = %f" % (c,d))
                if d > 60:
                    logger_analyzer.error("[ANAL]... big delay in processing %s = %f" % (c,d))
                elif d > 30:
                    logger_analyzer.warning("[ANAL]... noticeworthy delay in processing %s = %f" % (c,d))
                
                logger_analyzer.debug("[ANAL]... delay in processing %s = %f" % (c,d))
                
        
        logger_analyzer.debug("[ANAL]... processing 'called' chain: done")
                
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

def analyze_workers(ws):
    
    # do basic chain distribution
    ws.analyze()
    
    # analyze if logon events are handled in time
    ws.analyzer.analyze_called()

    # wow, dump whole chain database
    # ws.analyzer.print_chain()

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

def search_chain(ws,chsrch):
    return ws.search_chain(chsrch)

def search_workers(ws,srch_string_list,srch_string_list_neg=None,prefix_lines=True):
    logger_analyzer.debug("search_workers: searching positive ALL %s, negative ANY %s" % (str(srch_string_list),str(srch_string_list_neg)))
    ws.search_line(srch_string_list,srch_string_list_neg)
        
    f = open_file(ws.ca_log,"SEARCH")
    if f:
        nl = ws.write_tasks(f,{ "line search: %s/%s" % (str(srch_string_list),str(srch_string_list_neg)) : ws.search_line_result() })
        f.close()
        logger_analyzer.info("[D] %d non-empty lines written to the file" % (nl,))
        
        return True
    
    return False


    

"""
FIXME: some sane description
"""            
def split_workers(ws,calog_fnm,method,prefix_lines=True,task_separator=True):

    logger_state.info("Splitting by %s:" % (method,))

    if method == 'none':
        logger_state.info("Splitting skipped, per your request.")
        return

    opened_files = {}

    for t_id in ws.task_db_list:
        # because we are appeding gids (t_id here) immediatelly as they appear in the log,
        # we are not sure if the db was filled
        if t_id not in ws.task_db.keys():
            continue
    
        logger_state.debug("Processing task: %s, role=%s" % (t_id,ws.task_db[t_id]['role']))
       
        norm = os.path.normpath(calog_fnm)
        d = os.path.dirname(norm)
        f = os.path.basename(norm).split()[0]
        
        pid, id = t_id.split('-')
        
        target = os.path.join(d,f + ".DEFAULT.log")
        
        if method == "worker":
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
        
        if task_separator:
            opened_files[target].write("\n\n")
            
            
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

    parser.add_argument('--no-prefixes',dest='no_prefixes',default=False,help="While processing, each line is prefixed with it's task id. This command will avoid this.", const=True, nargs='?')
    
    parser.add_argument('-sb','--split-by', dest='split_by',default="none", choices=['none','workers','role','reorder'], 
        help="STATE: Split the log into separate files. Criteria: none, workers, role, reorder. Default: %(default)s",const="worker",nargs='?')
    parser.add_argument('-an','--analyze',dest='analyze',default=False,help="DEV: Go through the tasks and analyze the log. Under development!", const=True, nargs='?')
    parser.add_argument('-ls','--llsearch', dest='search', action="append", help='Line-level search: write to file all tasks where any line is matching this argument (currrently only regular expression is supported).')
    parser.add_argument('-lsn','--llsearch-neg', dest='search_neg', action="append", help='Line-level search: task match is canceled if any of this expressions are matched.')
    
    parser.add_argument('-chs','--chsearch', dest='chsearch', action="append", help='Chain-level search: write to file all tasks where chain is matched by regex. Form: --chsearch ip:<opt_type>:"<my-regexp>"')
    
    parser.add_argument('--debug-state', dest='debug_state',default=20,help='State machine verbosity: 50=critical, 40=errror, 30=warning, 20=information, 10=debug',const=10,nargs='?')
    parser.add_argument('--debug-analyzer', dest='debug_analyzer',default=20,help='Analyzer verbosity: 50=critical, 40=errror, 30=warning, 20=information, 10=debug',const=10,nargs='?')
    parser.add_argument('--debug-data', dest='debug_data',default=0,help='Dump data converted to JSON structures into a file',const=10,nargs='?')

    parser.add_argument('-m','--man',dest='manpage',default=False,help="Display verbose man page", const=True, nargs='?')
    parser.add_argument('-V','--version',dest='version',default=False,help="Display version and quit", const=True, nargs='?')
    args = parser.parse_args()
    return parser,args



man_main = """

     Embedded MANual page for
--== CANASTA tool by Ales Stibal, Fortinet L2 TAC in Prague ==--  

Important: Read bugs and limitations at the end of this manual page !!!

So you are interested in better understanding how this script does work and how 
you can use it efficiently. That is, indeed, The Right Thing(tm)!!! 

Important: All the result is ALWAYS chronologically ordered. You don't need 
to worry Canasta will display ANYTHING out of order.

CANASTA is the tool for better analysis of Collector Agent logs (and FSAE/FSSO 
in general in the future).
Canasta operates on the collector agent log. First what is Canasta doing is that 
it opens the file, and reads it line by line. After it's done, it can do various 
checks and is able to warn about noticeworthy details, which could be easily 
overlooked.

!! Please note that Canasta is new piece of code. Make sure that your judgements 
!! are not completely dependant on the Canasta outptut and are verified manually.


1. Separation to the (so called) tasks
======================================
The lines are matched against regular expresions, which will divide the lines at
first by the process/thread id.
Then, the second pass is  run, and the lines related to the particular  thread 
are also separated to chunks of lines, indicating  the one enclosed  TASK 
(say, processing  single logon event). 
Because Canasta knows, which tasks has been run by the worker, it is  also able 
to indicate  which (so called) ROLE the  worker represents, for example:
dcagent-io-recv, or logons-msg). 
During the time of using Canasta, you will get familiar with those role names. 
Now the file is processed.


At this moment, you can direct canasta script to save those tasks and lines, 
depending on which point of view you are interested in:
 
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
                            
 --split-by reorder :  Sometimes, you don't want to perform the heuristics and 
                       you just need to make the log more readable.
                       This will save all tasks chronologically to SINGLE file, 
                       ordered by task creation timestamp.
                       Result is almost the same as the orig. CollectorAgent.log, 
                       BUT the worker task lines are neighboring, so you can read 
                       the log without skipping other thread lines.
                       
                       Filename is created: CollectorAgent.log.reordered.log

--split-by none     :  that's indicating you are not looking for task separation 
                       into the files. Probably you want Canasta to do heurstics
                       only, so splitting the lines into files is not needed.
                           
 --no-prefixes      :  In all cases (except "none" is used), the lines  are 
                       prepended  by TASK ID. This task id consists of pair of 
                       decimal numbers separated by hyphen, e.g. 12312-34. 
                       This means the thread id is 12312, and the line belongs 
                       to 34th  task processed by  the thread.
                       For those who don't want to  have task-id at the every 
                       beginning of the line in files, please use this option. 
                       This will also prevent Canasta to separate tasks by two 
                       empty lines.
                       
                       
2. Line-level search
====================
Regarless you have instructed Canasta to save/split the tasks to file or not, 
now you have possibility to make some basic, not much intelligent search through
all of the tasks:

 --llsearch <regexp>:  Use regular expression to match each line in each task. 
                       If ANY task line matches your regexp, this whole task is 
                       considered as matching. Note that the regular expression
                       is just up to you. You can use any regex you want. Just 
                       take into the account that you are matching only single 
                       line.
                       All matching tasks are saved in the file
                       CollectorAgent.log.SEARCH.log.
                       This file is always rewritten and is NOT named by your 
                       regexp, as it can be quite complex.
                       
                       You can stack those line-level searches. If more searches 
                       are used, the task is considered matching, if ALL of 
                       --llsearch arguments match in the single task, regardless 
                       if the match is done on single or more lines.
                       
                       You can use  eg. --llsearch 'foo' --llsearch 'that' \\
                                --llsearch 'bars'.
                       
 --llsearch-neg <neg_regexp>:
                       If this option is used, any line in the task must not 
                       match this regexp. Matching this regular expression 
                       surpresses the final match decision.
                       Again, this option could be stacked like --llsearch. 
                       Bare in mind, the logic of final match surpressing is 
                       different: 
                       occurence of a match of any of neg_regexp arguments is 
                       surpressing the final task match.
                       This can be used for example to searching only in logon 
                       events, where group cache is not hit and new group lookup
                       was being done.
            
    NOTE: --llsearch is currently not aware of any chain searches (see below)
          and searches across all tasks.
          This is, nonetheless, on the short-term roadmap.
                       
                       
 3 Chain-level search
 ====================
 Maybe you remember that Canasta is working with some TASKs. Those tasks 
 are being recognized by message regex patterns, which also contain 'keywords'. 
 For example, we have keywords 'ip', 'user', 'wksta', 'domain', ... 
 Values of those keywords are stored, and based on them, there is built a tree
 structure, which is keeping relation between tasks which contain the same value 
 of each particular keyword.
 You can enable building process of this tree by passing '--analyze' argument.
 
 After the tree is built, you can search through of it. The tree has following 
 logic:
  KEYWORD   VALUE
 'wksta'-+-'pc1.net.local' -> list of TASKS: eg 345-1, 412-1
         +-'pc2.net.local' -> list of TASKS: eg 345-2, 412-2
 
 You can search this tree. See below:
 
 --chsearch <keyword>:<match_type>:<expression>
               keyword: which relation line you are looking for? 
                        ip     - ip1 or ip2 (see bellow)
                        wksta  - workstation name 
                        user   - username 
                        domain - domain of the user
                        ip1    - primary ip address reported by dcagent
                        ip2    - secondaty ip address reported by dcagent
                        called - logon even id : displays only messages of 
                                 dcagent-io-recv and logons-msg 
                                 workers. (see worker role)
            
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
            
            EXAMPLE 1:
               --chsearch wksta::'PC[0-1]+.lab.net'
            2:
               --chsearch ip::'10.31.8.0/24'
 
            All matching tasks are saved in the file CollectorAgent.log.CHAIN.log.
            
                       
 BUGS AND LIMITATIONS:
 =====================
 - Canasta can process only the DEBUG LEVEL logs. Other will show only incomplete
   and not reliable results.
   
 - The poller events are silently dropped
 - Analyzer is still in development
"""

version="""
    
CANASTA %s, tool for Fortinet Collector Agent troubleshooting.
Written by Ales Stibal <astibal@fortinet.com>, Fortinet, L2 TAC Prague (c) 2013    
""" % __version__

def print_man(arg_parser,args):
    print man_main
    
    
def main():
    arg_parser,args = parse_args()
    
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
    
    
    # Do the task used in all cases:
    start = time.time()

    ws = proc_calog(args.calog)          
    
    if args.split_by != 'none':
        split_workers(ws,args.calog,args.split_by, not args.no_prefixes)
    
    if args.chsearch and args.search:
        logger_state.error("Combination of chain search and line-level search is not supported.")
        logger_state.error("Contact sales@fortinet.com for a NFR ;-)")
        return
    
    
    # fill the condition with anything which will utilize analyzer engine
    if args.analyze or ( args.chsearch or args.chsearch ):
        logger_state.info("Analyzing:" )
        analyze_workers(ws)
        logger_state.info("done!")  

    if args.chsearch:
        logger_state.info("Chain search:" )
        search_chain(ws,args.chsearch)        
        logger_state.info("done!") 
        
    if args.search or args.search_neg:
        # if only negative search is present, set positive to match all lines
        if not args.search: args.search=['.*',]
        
        logger_state.info("Line search:")
        logger_state.debug("Line search: '%s': extra processing, please standby:" % (args.search,))
        search_workers(ws,args.search,args.search_neg,not args.no_prefixes)
        logger_state.info("done!")
        
    t = time.time() - start
    logger_state.info("Processing finished in %.2f secs!" % (t,))

    
    if int(args.debug_data):
        fnm = args.calog + '.json'
        logger_state.info("JSON dump to '%s'!" % (fnm,))
        f = open(fnm,'w+')
        json.dump(ws.data(),f,indent=4)
        f.close()
        logger_state.info("done!")




try:        
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
