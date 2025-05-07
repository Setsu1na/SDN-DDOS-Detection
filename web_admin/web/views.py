from django.shortcuts import render, redirect, HttpResponse

import csv
import datetime

SOCKFILE_RULE_ALERT = "/tmp/rule.alert"

SDN_FIREWALL_ROOT = "../SDN-Firewall/"

INTERACT_SHELL_TEST1 = "h2 " + SDN_FIREWALL_ROOT + "test/run.sh test1\n"
INTERACT_SHELL_TEST2 = "h2 " + SDN_FIREWALL_ROOT + "test/run.sh test2\n"
SHELL_START_MININET = SDN_FIREWALL_ROOT + "test/run.sh mininet"
SHELL_START_IDS = SDN_FIREWALL_ROOT + "test/run.sh ids"
SHELL_RESET = SDN_FIREWALL_ROOT + "test/run.sh reset"

LOG_ROOT = SDN_FIREWALL_ROOT + "log/"
RULE_ROOT = SDN_FIREWALL_ROOT + "rules/"

FILE_START_TIME = LOG_ROOT + "start.time"
FILE_EVENT_IMPORTANT = LOG_ROOT + "event.important"
FILE_FIREWALL_LOG = LOG_ROOT + "firewall.log"
FILE_IDS_LOG = LOG_ROOT + "ids.log"
FILE_ADMIN_LOG = LOG_ROOT + "admin.log"
FILE_PKT_ALL = LOG_ROOT + "pkt.all"

FILE_FIREWALL_RULE = RULE_ROOT + "firewall.rule"
FILE_IDS_RULE = RULE_ROOT + "ids.rule"

def indexContext():
    context = {}
    with open(FILE_START_TIME, "r") as f:
        context['time_info'] = f.readline()
    # context["rule_info"] = f.readline()
    pkts, threats = statistic()
    context['packet_info'] = len(pkts)
    
    total = 0
    for threat in threats:
        if threat['type'] != 'Normal':
            total += threat['count']
    context['threat_info'] = total

    percents = []
    for threat in threats:
        if threat['type'] != "Normal":
            percents.append((threat['count'], threat['count'] / total * 100 if total else 0))
    context['threat_type_info'] = percents

    new_rule_count = 0
    with open(FILE_EVENT_IMPORTANT, "r") as f:
        lines = list(csv.DictReader(f))
        for line in lines:
            if(line['event'].split('|')[0] == "new rule"):
                new_rule_count += 1

        events = []  
        for line in lines[-10:]:
            event = {}
            e = line['event'].split('|')
            if(e[0] == "new rule"):
                event['event'] = {"type":e[0], "rid":e[1], "action":e[2], "src":e[3], "dst":e[4]}
            elif(e[0] == "packet in"):
                event['event'] = {"type":e[0]}
            elif(e[0] == "alert"):
                event['event'] = {"type":e[0], "src":e[1], "attack_type":e[2]}
            event['timestamp'] = line['timestamp']
            event['reporter'] = line['reporter']
            events.append(event)
        for idx, event in enumerate(events[::-1]):
            event['no'] = idx + 1
            event['stats'] = '已处理'
        context["events"] = events[::-1]
    
    context['rule_info'] = new_rule_count

    return context

def sidebarContext(request):
    context = {}
    collapsed = request.GET.get('collapsed')
    menuopen = request.GET.get('menuopen')

    context["collapse"] = ""
    context["icon"] = "fa-angle-double-left"
    if(collapsed and int(collapsed)):
        context["collapse"] = "sidebar-collapse"
        context["icon"] = "fa-angle-double-right"
    
    context["menuopen"] = ["menu-open" if(menuopen and int(menuopen) & 1) else "",
                           "menu-open" if(menuopen and int(menuopen) >> 1) else ""]

    return context

def firewallLogContext(request):
    context = sidebarContext(request)
    with open(FILE_FIREWALL_LOG, "r") as f:
        logs = []
        for line in list(csv.DictReader(f)):
            log = {"auto":True}
            e = line['event'].split('|')
            if(e[0] in ["new rule", "remove rule", "match rule"]):
                log['event'] = {"type":e[0], "rid":e[1]}
                if e[0] != "match rule" and e[2] == "admin":
                    log['auto'] = False
            elif(e[0] == "packet in" or e[0] == "admin submit"):
                log['event'] = {"type":e[0]}
            elif(e[0] == "alert"):
                log['event'] = {"type":e[0], "attack_type":e[1]}
            log['s_ip'] = line['s_ip']
            log['s_port'] = line['s_port']
            log['d_ip'] = line['d_ip']
            log['d_port'] = line['d_port']
            log['action'] = line['action']
            log['timestamp'] = line['timestamp']

            logs.append(log)
        context['logs'] = logs[::-1]

    return context

def idsLogContext(request):
    context = sidebarContext(request)
    with open(FILE_IDS_LOG, "r") as f:
        context['logs'] = list(csv.DictReader(f))[::-1]
    
    return context

def adminLogContext(request):
    context = sidebarContext(request)
    with open(FILE_ADMIN_LOG, "r") as f:
        logs = []
        for line in list(csv.DictReader(f)):
            log = {}
            e = line['event'].split('|')
            if(e[0] == "new rule" or e[0] == "edit rule"):
                log['event'] = {"type":e[0], "over_rule_id":e[1], "rule_id":e[2], "s_ip":e[3], "s_port":e[4], "d_ip":e[5], "d_port":e[6], "action":e[7]}
            elif(e[0] == "remove rule" or e[0] == "up rule"):
                log['event'] = {"type":e[0], "rule_id":e[1]}
            elif(e[0] == "edit ids rule"):
                log['event'] = {"type":e[0], "label":e[1], "action":e[2]}

            log['timestamp'] = line['timestamp']
            log['time'] = str(datetime.datetime.now().year)[-2:] + "-" + log['timestamp'].split(' ')[0]
            log['timestamp'] = log['timestamp'].split(' ')[1]
            logs.append(log)
        
        context['logs'] = group(logs[::-1])     # group by timestamp
    print(context['logs'])
    return context        

def firewallRuleContext(request):
    context = sidebarContext(request)
    with open(FILE_FIREWALL_RULE, "r") as f:
        context['rules'] = list(csv.DictReader(f))

    return context

def idsRuleContext(request):
    context = sidebarContext(request)
    context['packets'], context['threats'] = statistic()
    
    rules = {}
    with open(FILE_IDS_RULE, "r") as f:
        for rule in list(csv.DictReader(f)):
            rules[rule['label']] = rule['action']
    
    for threat in context['threats']:
        threat['action'] = rules[threat['type']]

    context['threats'].append(context['threats'].pop(0))

    return context

def trafficStatisticContext(request):
    context = sidebarContext(request)
    context['packets'], context['threats'] = statistic()

    if(request.GET.get('target')):
        context['target'] = request.GET.get('target')  
    
    return context

def nodeStateContext(request):
    context = sidebarContext(request)
    context['switches'] = switches()

    return context

def systemTestContext(request):
    context = sidebarContext(request)
    return context

#def index(request):
#    return render(request, 'core/index.html', indexContext())

def index(request):
    return render(request, 'web/index.html',indexContext())

def firewallLog(request):
    return render(request, 'web/firewall_log.html', firewallLogContext(request))

def idsLog(request):
    return render(request, 'web/ids_log.html', idsLogContext(request))

def adminLog(request):
    return render(request, 'web/admin_log.html', adminLogContext(request))

def firewallRule(request):
    return render(request, 'web/firewall_rule.html', firewallRuleContext(request))

def idsRule(request):
    return render(request, 'web/ids_rule.html', idsRuleContext(request))

def trafficStatistic(request):
    return render(request, 'web/traffic_statistic.html', trafficStatisticContext(request))

def nodeState(request):
    return render(request, 'web/node_state.html', nodeStateContext(request))

def systemTest(request):
    return render(request, 'web/system_test.html', systemTestContext(request))

from collections import defaultdict
def group(logs):
    result = defaultdict(list)
    for log in logs:
        result[log['time']].append(log)
    return dict(result)

import json
def submitFirewallRule(request):
    data = json.loads(request.body.decode('utf-8'))
    rules = data['rules']
    t = timestamp()
    for rule in rules:
        if(rule[6] == "NOTIMESTAMP"):
            rule[6] = t

    # truncate file to zero
    with open(FILE_FIREWALL_RULE, "w") as f:
        f.write("id,s_ip,s_port,d_ip,d_port,action,timestamp,source\n")
        f.writelines([",".join(rule)+"\n" for rule in rules])

    # tell firewall to apply this overwritten firewall.rule
    send_alert()

    # log edit records
    records = data['records']
    with open(FILE_ADMIN_LOG, "a")  as f:
        f.writelines("|".join(record)+","+t+"\n" for record in records)
    
    return HttpResponse(t)

import socket
def send_alert():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect(SOCKFILE_RULE_ALERT)
    sock.send("anything-you-need-to-tell-firewall".encode())

def submitIDSRule(request):
    data = json.loads(request.body.decode('utf-8'))
    rules = data['rules']
    with open(FILE_IDS_RULE, "w") as f:
        f.write("label,action\n")
        f.writelines([",".join(rule)+"\n" for rule in rules])

    records = data['records']
    t = timestamp()
    with open(FILE_ADMIN_LOG, "a")  as f:
        f.writelines("edit ids rule|"+"|".join(record)+","+t+"\n" for record in records)

    return HttpResponse("")

import datetime
def timestamp():
    # time.localtime() and datetime.now() work well when mininet and ids are launched from terminal
    # but something goes wrong if launched from web_admin by calling subprocess()
    # the fetched time will be the utc rather than utc+8 time in the latter case
    # so covert utc to utc+8 manually here (also in utils.py whose timestamp() would be imported by ids)
    return (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).strftime("%m-%d %H:%M:%S")

from collections import Counter
def statistic():
    with open(FILE_PKT_ALL, "r") as f:
        pkts = list(csv.DictReader(f))[::-1]
    
    threats = []
    labels = [pkt['label'] for pkt in pkts]
    counter = Counter(labels)

    colors = ["#00a65a", "#dc3545", "#dc3545", "#dc3545", "#dc3545", "#dc3545", "#dc3545", "#dc3545"]
    for t in ['Normal', 'PortMap', 'NetBIOS', 'LDAP', 'MSSQL', 'UDP', 'UDPLag','SYN']:
        if t in counter.keys():
            threat = {"type":t, "count":counter[t], "percent":format(counter[t] / len(labels) *100, ".1f"), "color":colors.pop(0)}
        else:
            threat = {"type":t, "count":0, "percent":0, "color":colors.pop(0)}
        threats.append(threat)

    return pkts, threats

import urllib3
def switches():
    http = urllib3.PoolManager()

    switches = {}
    try:
        url = "http://127.0.0.1:8080/stats/switches"
        switch_ids = json.loads(http.request("GET", url).data.decode('utf-8'))

        url = "http://127.0.0.1:8080/stats/flow/"
        for sid in switch_ids:
            switches[sid] = json.loads(http.request("GET", url + str(sid)).data.decode('utf-8'))[str(sid)]

        for sid in switches:
            switches[sid] = sorted(switches[sid], key = lambda x:x['priority'], reverse = True)
    except:
        pass
    
    return switches

import subprocess
def test(request, test_id):
    global mininet, ids
    if(test_id == 1):
        mininet.stdin.write(INTERACT_SHELL_TEST1.encode())
        mininet.stdin.flush()
    elif(test_id == 2):
        mininet.stdin.write(INTERACT_SHELL_TEST2.encode())
        mininet.stdin.flush()
    
    return HttpResponse("")

mininet = None
ids = None
def start(request):
    global mininet, ids
    if(mininet):
        mininet.stdin.write("exit".encode())
        mininet.communicate()
    if(ids):
        ids.kill()
    mininet = subprocess.Popen(SHELL_START_MININET, stdin=subprocess.PIPE, shell=True)
    ids = subprocess.Popen(SHELL_START_IDS, shell=True)

    return HttpResponse("")

def reset(request):
    subprocess.run(SHELL_RESET, shell=True)
    start(request)
    return HttpResponse("")
