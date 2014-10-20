# -*- coding: utf-8 -*-
"""
Hydra support these checking:
asterisk cisco cisco-enable cvs firebird ftp ftps http[s]-{head|get} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] mssql mysql nntp oracle-listener oracle-sid pcanywhere pcnfs pop3[s] postgres rdp rexec rlogin rsh sip smb smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s] vmauthd vnc xmpp

This program is aim to serialize the data to call hydra.
YCom
"""
import sys
import os

import libnmap
from libnmap import parser

hydra_form = """asterisk cisco cisco-enable cvs firebird ftp ftps http-proxy http-proxy-urlenum icq imaps imap irc ldap2 ldap2s mssql mysql nntp oracle-listener oracle-sid pcanywhere pcnfs pop3 pop3s postgres rdp rexec rlogin rsh sip smb smtp smtps smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet telnets vmauthd vnc xmpp"""

hydra_table = hydra_form.split()

def get_ip_service_dict(NmapObj):
    ip_services = {}
    for host in NmapObj.hosts:
        if len(host.services)!=0:
            service_list = []
            for serv in host.services:
                if serv.open() and serv.service in hydra_table:
                    service_list.append([serv.service,serv.port])
            if len(service_list)!=0:
                ip_services[host._ipv4_addr] = service_list
    return ip_services

def gen_target_file_by_dic(ip_services_dic,temp_file):
    with open(temp_file,'a+') as f:
        for ip in ip_services_dic:
            for servs in ip_services_dic[ip]:
                line = "{0}://{1}\n".format(servs[0],ip)
                f.write(line)
    print("Target File successed generated!")
    return True

def do_start():
    if len(sys.argv) != 3:
        raise Exception('Error argument number!')

    _date = sys.argv[1]
    xml = sys.argv[2]
    temp_file = _date+'.txt'
    nmap_parser = parser.NmapParser()
    nmap_obj = nmap_parser.parse_fromfile(xml)
    ip_serv_dict = get_ip_service_dict(nmap_obj)
    if gen_target_file_by_dic(ip_serv_dict,temp_file) != True:
        raise Exception('Error while parsing nmap!')

    import subprocess
    hydra_cmd = "hydra -L /root/scans/username.lst -P /root/scans/password.lst -o {0} {1}"
    with open(temp_file) as f:
        for line in f:
            cmd = hydra_cmd.format('cracked-'+_date,line)
            subprocess.call(cmd,shell=True)

if __name__ == '__main__':
    do_start()
