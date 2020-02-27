import argparse
import os
import signal
import subprocess
import time

parser = argparse.ArgumentParser(description='Start remote test.')
parser.add_argument('servers', type=int,
                    help='number of servers')
parser.add_argument('mailboxes', type=int,
                    help='number of mailboxes')
parser.add_argument('clients', type=int,
                    help='number of clients')
parser.add_argument('f', type=float, default=0.2,
                    help='fraction of malicious servers')
parser.add_argument('kill', type=int,
                    help='kill all process first [0|1]')

args = parser.parse_args()
kill = args.kill == 1

ips = []
with open('remote_ips') as f:
    lines = f.readlines()
    for line in lines:
        ips.append(line.rstrip('\n'))

gopath = os.getenv('GOPATH')
src_dir = 'github.com/kwonalbert/xrd'

# os.system('go install %s/cmd/coordinator' % (src_dir))
# os.system('go install %s/cmd/config' % (src_dir))
# os.system('go install %s/cmd/server' % (src_dir))
# os.system('go install %s/cmd/client' % (src_dir))
# os.system('go install %s/cmd/mailbox' % (src_dir))

server_ips = []
mailbox_ips = []
client_ips = []
for i in range(args.servers):
    server_ips.append((ips[i],8000))
for i in range(args.mailboxes):
    mailbox_ips.append((ips[i],9000))
for i in range(args.clients):
    client_ips.append((ips[i],10000))

server_file_flag = '--servers %s/server.config' % os.getcwd()
group_file_flag = '--groups %s/group.config' % os.getcwd()
mailbox_file_flag = '--mailboxes %s/mailbox.config' % os.getcwd()
client_file_flag = '--clients %s/client.config' % os.getcwd()

base_addr_flag = '--addr %s:%d'

# create the config files
print("create config files")
iplist = open('ip.list', 'w')
for ip in server_ips:
    iplist.write('server,%s:%d\n' % ip)
for ip in mailbox_ips:
    iplist.write('mailbox,%s:%d\n' % ip)
for ip in client_ips:
    iplist.write('client,%s:%d\n' % ip)
iplist.close()

os.system('%s/bin/config --f %f' % (gopath, args.f)) # this expects ip.list

# launch the mailboxes
print("launching mailboxes")
mprocesses = []
for i in range(args.mailboxes):
    cmd = " ".join(['ssh',
                    '-o StrictHostKeyChecking=no',
                    '-i ~/kwonal.pem',
                    mailbox_ips[i][0],
                    '%s/bin/mailbox' % gopath + ' ' + \
                    base_addr_flag % mailbox_ips[i]  + ' ' + mailbox_file_flag])
    p = subprocess.Popen(cmd, stdout=None, stderr=None, stdin=subprocess.PIPE, shell=True)
    mprocesses.append(p)
time.sleep(0.5)

# launch the servers
print("launching servers")
sprocesses = []
for i in range(args.servers):
    cmd = " ".join(['ssh',
                    '-o StrictHostKeyChecking=no',
                    '-i ~/kwonal.pem',
                    server_ips[i][0],
                    '%s/bin/server' % gopath + ' ' + \
                    base_addr_flag % server_ips[i] + ' ' + \
                    server_file_flag + ' ' + \
                    group_file_flag + ' ' + \
                    mailbox_file_flag])
    p = subprocess.Popen(cmd, stdout=None, stderr=None, stdin=subprocess.PIPE, shell=True)
    sprocesses.append(p)
time.sleep(0.5)

# launch the clients
print("launching clients")
cprocesses = []
for i in range(args.clients):
    cmd = " ".join(['ssh',
                    '-o StrictHostKeyChecking=no',
                    '-i ~/kwonal.pem',
                    client_ips[i][0],
                    '%s/bin/client' % gopath + ' ' + \
                    base_addr_flag % client_ips[i] + ' ' + \
                    server_file_flag + ' ' + \
                    group_file_flag + ' ' + \
                    mailbox_file_flag + ' ' + \
                    client_file_flag])
    p = subprocess.Popen(cmd, stdout=None, stderr=None, stdin=subprocess.PIPE, shell=True)
    cprocesses.append(p)
time.sleep(1.0)

# start the coordinator
coordinator_flags = " ".join([server_file_flag,
                              group_file_flag,
                              mailbox_file_flag,
                              client_file_flag])
os.system('%s/bin/coordinator %s' % (gopath, coordinator_flags))

print("cleanup processes")
for p in cprocesses:
    os.kill(p.pid, signal.SIGINT)
for p in sprocesses:
    os.kill(p.pid, signal.SIGINT)
for p in mprocesses:
    os.kill(p.pid, signal.SIGINT)

os.remove('server.config')
os.remove('group.config')
os.remove('mailbox.config')
os.remove('client.config')
os.remove('ip.list')
