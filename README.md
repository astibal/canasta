# Overview
Canasta is tool for helping to read FSSO CA CollectorAgent.log file.

Most typical tasks is running 

```--split-by reorder
```
or 
```--llsearch fail
```
or 
``` --chseach 'wksta::PC123'
```


# HOW IT WORKS -- dump from manual page (canasta.py -m)

## 1. Separation to the tasks

```
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
   
```                    
                       
## Line-level search

```
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
                       
                       You can use  eg. --llsearch 'foo' --llsearch 'that' \
                                --llsearch 'bars'.

                       
 --llsearch-neg <neg_regexp>:
                       If this option is used, any line in the task must not 
                       match this regexp, regardless what --llsearch result is.
                       Matching this regular expression prevents the task to
                       be finally positively matched.
                       
                       This option could be used several times too. Task
                       matches ANY of --llsearch-neg expressions is prevented 
                       to be finally matched.
                                   
 
```
                    
## Chain-level search

``` 
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
            
``` 

# Interactive mode [under development]

```
 Are you doing some more complex research with large data? Then parsing all files
 over again is tedious. There was an intention to save "cache" data file with
 result of parsing, however, loading this file would take similar time compared to
 parse it again.
 Interactive mode partially solves this problem, since it loads data just once. 
 It's up to you what you will really do with them. Commands are very similar as the
 arguments of canasta itself. Please take a look on 'help' command.
 
 Interactive mode is activated with --interactive, or -i option.
                       
```