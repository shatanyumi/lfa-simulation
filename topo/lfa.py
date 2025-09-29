#!/usr/bin/env python3
"""
Custom topology for Containernet with embedded LFA simulation.
- Fixed bot_hosts (h1-h30) and normal_hosts (h31-h41)
- Captures mixed traffic on s6
- Disables IPv6 to remove ICMPv6 packets
- Uses idcg{g}h{i}.lfa.com for IDC hosts, resolves via dns_server
- Prevents traffic leakage, fixes TypeError, optimizes cpu_quota and r2q
"""

import os
import time
import random
import logging
import threading
import subprocess
import uuid
import shlex

from subprocess import PIPE, STDOUT, CalledProcessError, run
from queue import Queue 
from mininet.net import Containernet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

# Logging
logging.basicConfig(filename='/tmp/lfa_simulation.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('lfa_simulation')

# Separate loggers for normal and attack traffic
normal_logger = logging.getLogger('normal_traffic')
nfh = logging.FileHandler('/tmp/normal_traffic_log.txt')
nfh.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
normal_logger.addHandler(nfh)

attack_logger = logging.getLogger('attack_traffic')
afh = logging.FileHandler('/tmp/attack_traffic_log.txt')
afh.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
attack_logger.addHandler(afh)

# Utils
def get_s6_to_s42_interface(net):
    try:
        s6, s42 = net.get('s6', 's42')
        links = s6.connectionsTo(s42)
        if links:
            intf_s6, _ = links[0]
            logger.info(f"Found s6<->s42: {intf_s6.name}")
            return intf_s6.name
    except Exception as e:
        logger.error(f"Error finding s6<->s42: {e}")
    return None

def raw_ip(host_obj):
    try:
        ip = host_obj.IP()
        if '/' in ip:
            ip = ip.split('/')[0]
        return ip
    except Exception as e:
        logger.error(f"Error getting IP for {host_obj.name}: {e}")
        return None

# ---- Time sync helpers ----
def _run(cmd, timeout=30):
    """Run shell command, return (retcode, stdout). Uses shell=False style where possible."""
    if isinstance(cmd, str):
        # split for safety where appropriate
        try:
            parts = shlex.split(cmd)
        except Exception:
            parts = [cmd]
    else:
        parts = cmd
    try:
        res = run(parts, stdout=PIPE, stderr=STDOUT, timeout=timeout, check=False, text=True)
        return res.returncode, (res.stdout or '').strip()
    except CalledProcessError as e:
        return e.returncode, (e.output or '').strip()
    except Exception as e:
        return 255, str(e)

def is_root():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def _sudo_prefix():
    return [] if is_root() else ['sudo']

def enable_ntp():
    """Enable systemd NTP sync. Return True if succeeded (command executed)."""
    # Try timedatectl first
    rc, out = _run(_sudo_prefix() + ['timedatectl', 'set-ntp', 'true'])
    if rc == 0:
        logger.info("timedatectl: enabled NTP")
        return True
    # fallback: try start chronyd or ntpd
    rc, out = _run(_sudo_prefix() + ['systemctl', 'start', 'chronyd'])
    if rc == 0:
        logger.info("Started chronyd as fallback")
        return True
    rc, out = _run(_sudo_prefix() + ['systemctl', 'start', 'ntp'])
    if rc == 0:
        logger.info("Started ntp as fallback")
        return True
    logger.warning("Failed to enable NTP via timedatectl/systemctl (rc=%s, out=%s)", rc, out)
    return False

def disable_ntp():
    """Disable systemd NTP sync (prevents big step corrections during experiment)."""
    rc, out = _run(_sudo_prefix() + ['timedatectl', 'set-ntp', 'false'])
    if rc == 0:
        logger.info("timedatectl: disabled NTP")
        return True
    # fallback: stop chronyd/ntpd
    rc, out = _run(_sudo_prefix() + ['systemctl', 'stop', 'chronyd'])
    if rc == 0:
        logger.info("Stopped chronyd as fallback")
        return True
    rc, out = _run(_sudo_prefix() + ['systemctl', 'stop', 'ntp'])
    if rc == 0:
        logger.info("Stopped ntp as fallback")
        return True
    logger.warning("Failed to disable NTP via timedatectl/systemctl (rc=%s, out=%s)", rc, out)
    return False

def ntp_is_synchronized():
    """Return True if the system clock is synchronized (tries several checks)."""
    # 1) timedatectl property
    rc, out = _run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    if rc == 0 and out.lower().strip() in ('yes', 'true', '1'):
        return True
    # 2) chronyc tracking
    rc, out = _run(['chronyc', 'tracking'])
    if rc == 0 and 'Reference ID' in out:
        # check stratum or 'Leap status'
        if 'Leap status' in out or 'Ref time' in out:
            return True
    # 3) ntpstat
    rc, out = _run(['ntpstat'])
    if rc == 0 and 'synchronised' in out.lower():
        return True
    # fallback: compare system time to remote NTP server using ntpdate -q (non-changing)
    rc, out = _run(_sudo_prefix() + ['ntpdate', '-q', 'pool.ntp.org'], timeout=20)
    if rc == 0 and 'server' in out:
        # parse typical output line, e.g. "server 91.189.94.4, stratum 2, offset 0.000123"
        # if we get output, assume reachable (not perfect)
        return True
    return False

def wait_for_ntp_sync(timeout=60, poll=2):
    """Wait up to timeout seconds for NTP to report synchronized. Returns True on success."""
    start = time.time()
    while time.time() - start < timeout:
        ok = ntp_is_synchronized()
        if ok:
            logger.info("System clock synchronized")
            return True
        time.sleep(poll)
    logger.warning("Timed out waiting for NTP sync after %s seconds", timeout)
    return False

def sync_time_once_fallback():
    """Try a one-shot ntpdate to sync immediately if timedatectl not available."""
    rc, out = _run(_sudo_prefix() + ['ntpdate', '-u', 'pool.ntp.org'], timeout=30)
    if rc == 0:
        logger.info("ntpdate sync succeeded")
        return True
    logger.warning("ntpdate sync failed (rc=%s): %s", rc, out)
    return False

def disable_ipv6(hosts):
    for h in hosts:
        h.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        h.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
        for intf in h.intfList():
            h.cmd(f"sysctl -w net.ipv6.conf.{intf}.disable_ipv6=1")

def generate_normal_traffic(net, normal_hosts, idc_hosts, dns_server_ip, duration=360, thread_id=None):
    services = ['http', 'https', 'ssh', 'dns', 'ntp', 'stun']
    weights = [0.25, 0.25, 0.15, 0.15, 0.10, 0.10]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/14.1",
        "Mozilla/5.0 (X11; Linux x86_64) Firefox/89.0"
    ]
    file_types = ['smallfile', 'mediumfile', 'largefile']
    file_weights = [0.5, 0.3, 0.2]
    request_types = ['GET', 'POST', 'HEAD']
    request_weights = [0.6, 0.3, 0.1]
    procs = []

    meta_path = f"/tmp/normal_traffic_meta_{thread_id or uuid.uuid4().hex[:6]}.txt"
    with open(meta_path, 'w') as meta:
        meta.write('start_ts,end_ts,src_host,dst_domain,protocol,rate_kbps,duration,file_type,request_type\n')
    
    start = time.time()
    tcp_samples = udp_samples = 0

    while time.time() - start < duration:
        src = random.choice(normal_hosts)
        dst = random.choice(list(idc_hosts.values()))
        dst_ip = raw_ip(dst)
        if not dst_ip:
            continue
        dst_domain = f"idcg{dst_ip.split('.')[2]}h{dst_ip.split('.')[3]}.lfa.com"
        service = random.choices(services, weights)[0]
        rate = random.randint(100, 1000)
        req_duration = random.randint(10, 30)
        num_reqs = random.randint(5, 10) if service in ['http', 'https'] else 1
        round_start = time.time()

        for _ in range(num_reqs):
            file_type = random.choices(file_types, file_weights)[0] if service in ['http', 'https'] else None
            req_type = random.choices(request_types, request_weights)[0] if service in ['http', 'https'] else None
            ua = random.choice(user_agents)
            try:
                if service == 'http':
                    cmd = f'curl -A "{ua}" --interface {src.IP()} -o /dev/null --connect-timeout 10 --resolve {dst_domain}:80:{dst.IP()} http://{dst_domain}/{file_type} --limit-rate {rate//num_reqs}k --max-time {req_duration//num_reqs}'
                elif service == 'https':
                    cmd = f'curl -k -A "{ua}" --interface {src.IP()} -o /dev/null --connect-timeout 10 --resolve {dst_domain}:443:{dst.IP()} https://{dst_domain}/{file_type} --limit-rate {rate//num_reqs}k --max-time {req_duration//num_reqs}'
                elif service == 'ssh':
                    cmd = f'sshpass -p admin ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 admin@{dst_domain} "echo test"'
                elif service == 'dns':
                    cmd = f'dig @{dns_server_ip} {dst_domain} {random.choice(["A", "AAAA", "MX"])} +short +tries=2 +timeout=3'
                elif service == 'ntp':
                    cmd = f'ntpdate -q {dst_domain}'
                elif service == 'stun':
                    cmd = f'stun {dst_domain}:3478'
                else:
                    continue
                proc = src.popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                proc.stdout.close()
                proc.stderr.close()
                procs.append((src.name, proc))
                normal_logger.info(f"{src.name} -> {dst_domain} service={service} rate={rate//num_reqs}k")
                
                with open(meta_path, 'a') as meta:
                    meta.write(f"{round_start},{round_start+(req_duration//num_reqs)},{src.name},{dst_domain},{service},{rate//num_reqs},{req_duration//num_reqs},{file_type or 'N/A'},{req_type or 'N/A'}\n")
                    meta.flush()
                
                if service in ['http', 'https', 'ssh']:
                    tcp_samples += 1
                else:
                    udp_samples += 1
            except Exception as e:
                normal_logger.error(f"Normal traffic failed: {e}")
            
            time.sleep(random.uniform(0.02, 0.2))
    
    tcp_ratio = tcp_samples / (tcp_samples + udp_samples) if tcp_samples + udp_samples > 0 else 0
    normal_logger.info(f"Normal traffic done. TCP: {tcp_samples}, UDP: {tcp_ratio:.2f}")
    
    for _, proc in procs:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                
    return procs

def generate_attack_traffic(net, bot_hosts, decoys, dns_server_ip, duration=360, switch_interval=10, rate_mbps=10):
    procs = []
    meta_path = '/tmp/attack_traffic_meta.txt'
    with open(meta_path, 'w') as meta:
        meta.write('start_ts,end_ts,subnet,targets,protocol,src_bot,target_domain,rate_kbps,duration\n')
    start = time.time()
    rate = max(50, int(rate_mbps * 1000 / len(bot_hosts)))
    attack_types = ['http', 'https', 'ssh', 'udp']
    weights = [0.35, 0.35, 0.10, 0.20]

    while time.time() - start < duration:
        subnet, targets = random.choice(list(decoys.items()))
        round_start = time.time()
        for bot in bot_hosts:
            chosen = random.sample(targets, min(2, len(targets)))
            attacks = random.choices(attack_types, weights=weights, k=random.randint(2, 3))
            for tgt in chosen:
                attack_rate = random.randint(int(rate * 0.8), int(rate * 2.0))
                attack_duration = random.randint(10, 25)

                try:
                    g = int(tgt.split('g')[1].split('h')[0])
                    i = int(tgt.split('h')[1].split('.')[0])
                    tgt_ip = f"10.0.{g}0.{i+1}"
                except:
                    tgt_ip = "10.0.0.1" # Fallback
                
                for at in attacks:
                    try:
                        if at == 'http':
                            cmd = f'curl -A Mozilla --interface {bot.IP()} --connect-timeout 10 --resolve {tgt}:80:{tgt_ip} http://{tgt}/largefile --limit-rate {attack_rate}k --max-time {attack_duration}'
                        elif at == 'https':
                            cmd = f'curl -k -A Mozilla --interface {bot.IP()} --connect-timeout 10 --resolve {tgt}:443:{tgt_ip} https://{tgt}/largefile --limit-rate {attack_rate}k --max-time {attack_duration}'
                        elif at == 'ssh':
                            cmd = f'sshpass -p admin scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 /tmp/dummy_file admin@{tgt}:/tmp'
                        elif at == 'udp':
                            port = random.randint(1024, 65535)
                            cmd = f'hping3 -2 -p {port} -d {random.randint(64, 256)} --count 20 --rand-source --interval u50000 {tgt}'
                        else:
                            continue
                        proc = bot.popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        proc.stdout.close()
                        proc.stderr.close()
                        procs.append((at, proc))
                        attack_logger.info(f"{bot.name} -> {tgt} {at} rate={attack_rate}k")
                        with open(meta_path, 'a') as meta:
                            meta.write(f"{round_start},{round_start+attack_duration},{subnet},{targets},{at},{bot.name},{tgt},{attack_rate},{attack_duration}\n")
                            meta.flush()
                    except Exception as e:
                        attack_logger.error(f"Attack {at} failed: {e}")
        time.sleep(switch_interval)
    
    for _, proc in procs:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

    return procs

def _normal_worker_q(net, normal_hosts, idc_hosts_map, dns_server_ip, duration, thread_id, q):
    procs = generate_normal_traffic(
        net, normal_hosts, idc_hosts_map, dns_server_ip,
        duration=duration, thread_id=thread_id
    )
    q.put(procs)



def control_traffic(net, normal_hosts, idc_hosts_map, bot_hosts, decoys, dns_server_ip):
    normal_procs = []
    attack_procs = []

    threads = []
    q = Queue()

    THREADS_NORMAL = 3
    NORMAL_DURATION = 360
    for i in range(THREADS_NORMAL):
        tid = f"n{i+1}"
        t = threading.Thread(
            target=_normal_worker_q,
            args=(net, normal_hosts, idc_hosts_map, dns_server_ip, NORMAL_DURATION, tid, q),
            daemon=True
        )
        threads.append(t)
        t.start()

    attack_procs.extend(
        generate_attack_traffic(net, bot_hosts, decoys, dns_server_ip)
    )

    for t in threads:
        t.join()

    while not q.empty():
        normal_procs.extend(q.get())

    return normal_procs + attack_procs

def start_tcpdump(switch, intf, pcap_file):
    switch.cmd(f'tcpdump -i {intf}  -s 0 -B 8192 -w {pcap_file} ip 2>/tmp/tcpdump_error.log &')
    time.sleep(5)
    if not switch.cmd('pgrep tcpdump'):
        logger.error("tcpdump failed to start, check /tmp/tcpdump_error.log")
        return False
    logger.info(f"Started tcpdump on {switch.name}:{intf}")
    return True

def stop_tcpdump(switch):
    switch.cmd('pkill -2 -f tcpdump')
    time.sleep(5)
    logger.info(f"Stopped tcpdump on {switch.name}")

# Main
def CernetNetwork():
    info("==================== Building Cernet Topology ====================\n")
    net = Containernet(build=False, ipBase='10.0.0.0/12', autoSetMacs=True)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)

    # Switches
    switches = {f's{i}': net.addSwitch(f's{i}', cls=OVSKernelSwitch, failMode='standalone') for i in range(1, 48)}
    for i in range(1, 48):
        switches[f's{i}'].cmd(f'ifconfig s{i} 10.0.8.{i}')

    # Hosts
    hosts = {f'h{i}': net.addHost(f'h{i}', ip=f'10.0.0.{i}/12') for i in range(1, 42)}
    bot_hosts = [hosts[f'h{i}'] for i in range(1, 31)]
    normal_hosts = [hosts[f'h{i}'] for i in range(31, 42)]

    # IDC Dockers
    idc_hosts = {}
    for g in range(1, 6):
        for i in range(1, 13):
            name = f'idc_g{g}_h{i}'
            ip = f'10.0.{g}0.{i+1}/12'
            idc_hosts[name] = net.addDocker(name, ip=ip, dimage='idc:latest', ports=[80, 443, 22, 53, 123, 3478], 
                                        cpu_quota=20000, mem_limit='512m', dcmd='/entrypoint.sh', network='none')

    # DNS Server
    dns_server = net.addDocker('dns_server', ip='10.0.100.2/12', dimage='idc:latest', ports=[53], 
                               cpu_quota=20000, mem_limit='512m', dcmd='/entrypoint.sh', network='none')
    
    dns_server_ip = '10.0.100.2'

    # Links
    for i in range(1, 42):
        net.addLink(switches[f's{i}'], hosts[f'h{i}'], cls=TCLink, bw=1.0, delay='0ms', r2q=1)
    for g, sw in [(1, 's43'), (2, 's44'), (3, 's45'), (4, 's46'), (5, 's47')]:
        for i in range(1, 13):
            net.addLink(idc_hosts[f'idc_g{g}_h{i}'], switches[sw], cls=TCLink, bw=2.0, delay='0.5ms', r2q=1)
    city_links = [
        (1, 7, {'bw': 2.0, 'delay': '1.7244ms'}), (1, 8, {'bw': 155.0, 'delay': '1.957ms'}),
        (2, 33, {'bw': 155.0, 'delay': '7.2871ms'}), (2, 4, {'bw': 2.0, 'delay': '2.2131ms'}),
        (3, 25, {'bw': 155.0, 'delay': '3.8152ms'}), (3, 33, {'bw': 1000.0, 'delay': '5.6519ms'}),
        (4, 33, {'bw': 155.0, 'delay': '5.2272ms'}), (5, 9, {'bw': 2.0, 'delay': '2.4174ms'}),
        (5, 8, {'bw': 155.0, 'delay': '2.3121ms'}), (6, 22, {'bw': 128.0, 'delay': '9.4892ms'}),
        (7, 8, {'bw': 155.0, 'delay': '2.5722ms'}), (8, 9, {'bw': 155.0, 'delay': '0.5346ms'}),
        (8, 10, {'bw': 155.0, 'delay': '2.6141ms'}), (8, 25, {'bw': 1000.0, 'delay': '4.2502ms'}),
        (8, 26, {'bw': 1000.0, 'delay': '2.8761ms'}), (8, 30, {'bw': 155.0, 'delay': '6.1602ms'}),
        (10, 27, {'bw': 155.0, 'delay': '1.0909ms'}), (11, 22, {'bw': 128.0, 'delay': '8.7544ms'}),
        (12, 22, {'bw': 128.0, 'delay': '8.7544ms'}), (13, 28, {'bw': 2.0, 'delay': '2.8743ms'}),
        (13, 29, {'bw': 155.0, 'delay': '3.9196ms'}), (13, 14, {'bw': 1000.0, 'delay': '1.3441ms'}),
        (14, 22, {'bw': 128.0, 'delay': '0.5499ms'}), (15, 16, {'bw': 1000.0, 'delay': '1.8082ms'}),
        (16, 17, {'bw': 1000.0, 'delay': '2.5927ms'}), (16, 18, {'bw': 1000.0, 'delay': '1.4159ms'}),
        (16, 22, {'bw': 1000.0, 'delay': '3.1891ms'}), (16, 30, {'bw': 155.0, 'delay': '6.0393ms'}),
        (19, 22, {'bw': 128.0, 'delay': '4.3706ms'}), (20, 22, {'bw': 128.0, 'delay': '4.3706ms'}),
        (21, 25, {'bw': 1000.0, 'delay': '1.6263ms'}), (21, 29, {'bw': 155.0, 'delay': '0.7263ms'}),
        (22, 35, {'bw': 155.0, 'delay': '13.0311ms'}), (22, 40, {'bw': 155.0, 'delay': '2.1056ms'}),
        (22, 41, {'bw': 155.0, 'delay': '2.0428ms'}), (22, 23, {'bw': 155.0, 'delay': '1.3499ms'}),
        (22, 24, {'bw': 2.0, 'delay': '6.347ms'}), (22, 25, {'bw': 1000.0, 'delay': '5.3593ms'}),
        (22, 32, {'bw': 1000.0, 'delay': '3.1607ms'}), (22, 29, {'bw': 1000.0, 'delay': '4.5646ms'}),
        (22, 38, {'bw': 155.0, 'delay': '4.6362ms'}), (24, 30, {'bw': 155.0, 'delay': '3.0828ms'}),
        (25, 33, {'bw': 1000.0, 'delay': '3.0668ms'}), (25, 26, {'bw': 155.0, 'delay': '1.4911ms'}),
        (25, 29, {'bw': 1000.0, 'delay': '2.3321ms'}), (25, 32, {'bw': 155.0, 'delay': '2.3771ms'}),
        (27, 30, {'bw': 155.0, 'delay': '3.1051ms'}), (28, 29, {'bw': 155.0, 'delay': '2.4ms'}),
        (29, 30, {'bw': 1000.0, 'delay': '1.3738ms'}), (30, 31, {'bw': 1000.0, 'delay': '0.831ms'}),
        (33, 38, {'bw': 155.0, 'delay': '6.2282ms'}), (34, 38, {'bw': 155.0, 'delay': '10.7636ms'}),
        (34, 39, {'bw': 2.0, 'delay': '8.4826ms'}), (36, 37, {'bw': 2.0, 'delay': '0.9748ms'}),
        (36, 38, {'bw': 155.0, 'delay': '3.5552ms'}), (37, 38, {'bw': 155.0, 'delay': '2.5809ms'}),
        (38, 39, {'bw': 155.0, 'delay': '2.6678ms'}), (40, 41, {'bw': 2.0, 'delay': '1.7086ms'})
    ]
    for s1, s2, params in city_links:
        net.addLink(switches[f's{s1}'], switches[f's{s2}'], cls=TCLink, r2q=1, **params)
    net.addLink(switches['s6'], switches['s42'], cls=TCLink, bw=5.0, delay='2.1ms', r2q=1)
    for s in ['s43', 's44', 's45', 's46', 's47']:
        net.addLink(switches['s42'], switches[s], cls=TCLink, bw=100.0, delay='0.5ms', r2q=1)
    net.addLink(switches['s22'], dns_server, cls=TCLink, bw=100.0, delay='0ms', r2q=1)

        # -------- before build/start network --------
    info('*** Ensuring system time is synchronized before starting experiment\n')
    # try enabling and wait for sync
    if not enable_ntp():
        logger.warning("Could not enable NTP via system tools; attempting manual ntpdate")
        sync_time_once_fallback()
    else:
        # wait for synchronization (up to 60s)
        wait_for_ntp_sync(timeout=60, poll=2)

    # Optionally disable NTP to prevent step changes during experiment
    info('*** Disabling automatic NTP adjustments during experiment\n')
    disable_ntp()

    # Build and start
    net.build()
    c0.start()
    for sw in switches.values():
        sw.start([c0])
    info('*** Network started\n')
    info('==================== LFA attack simulation ====================\n')
    # Setup hosts
    for h in list(hosts.values()) + list(idc_hosts.values()) + [dns_server]:
        h.cmd('dd if=/dev/urandom of=/tmp/dummy_file bs=1M count=2 > /dev/null 2>&1')
        h.cmd('dd if=/dev/urandom of=/tmp/dummy_small bs=10K count=1 > /dev/null 2>&1')
        h.cmd('dd if=/dev/urandom of=/tmp/dummy_medium bs=100K count=1 > /dev/null 2>&1')
        h.cmd('dd if=/dev/urandom of=/tmp/dummy_large bs=1M count=1 > /dev/null 2>&1')

    # Disable IPv6
    disable_ipv6(list(hosts.values()) + list(idc_hosts.values()) + [dns_server])

    # RSTP
    info('*** Enabling RSTP on switches\n')
    info('*** Expected time: 1.5 min (90 sec)\n')
    for i in range(1, 48):
        switches[f's{i}'].cmd(f'ovs-vsctl set bridge s{i} rstp_enable=true')
    time.sleep(90)

    # Start traffic capture
    info('*** Starting traffic capture on s6\n')
    s6 = net.get('s6')
    intf = get_s6_to_s42_interface(net)
    info('*** Capturing on interface: {}\n'.format(intf))
    if not intf:
        logger.error("Failed to find s6-s42 interface, stopping network")
        net.stop()
        return
    pcap_file = '/tmp/s6_mixed_traffic.pcap'
    if not start_tcpdump(s6, intf, pcap_file):
        info('*** tcpdump failed to start, stopping network\n')
        net.stop()
        return

    # Generate traffic
    info('*** Generating traffic\n')
    decoys = {f'10.0.{g}0.0': [f'idcg{g}h{i}.lfa.com' for i in range(1, 13)] for g in range(1, 6)}
    procs = control_traffic(net, normal_hosts, idc_hosts, bot_hosts, decoys, dns_server_ip)

    # Cleanup
    info('*** Stopping traffic capture\n')
    stop_tcpdump(s6)
    time.sleep(5)
    info('*** Cleaning up processes\n')
    for _, proc in procs:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                logger.info(f"Killed lingering process: {proc.pid}")
    if os.path.exists(pcap_file):
        os.system(f'sudo cp {pcap_file} ~/study/iar/topo/')
        info(f'*** PCAP copied to ~/study/iar/topo/, size: {os.path.getsize(pcap_file)} bytes\n')
        logger.info(f"PCAP copied, size: {os.path.getsize(pcap_file)} bytes")

    info('*** Simulation complete. You can analyze the PCAP file.\n')
    info('*** Restoring NTP settings after experiment\n')
    # re-enable system time synchronization
    try:
        enable_ntp()
    except Exception as e:
        logger.warning("Failed to re-enable NTP: %s", e)
    
    info('==================== Starting CLI ====================\n')
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    CernetNetwork()