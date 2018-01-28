#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2014-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import socket
import struct
import re
import logging

from shadowsocks import common, lru_cache, eventloop, shell


CACHE_SWEEP_INTERVAL = 30

VALID_HOSTNAME = re.compile(br"(?!-)[A-Z\d\-_]{1,63}(?<!-)$", re.IGNORECASE)

common.patch_socket()

# rfc1035
# format
# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+
#
# header
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    NSCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

QTYPE_ANY = 255
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_CNAME = 5
QTYPE_NS = 2
QCLASS_IN = 1


def build_address(address):
    address = address.strip(b'.')
    labels = address.split(b'.')
    results = []
    for label in labels:
        l = len(label)
        if l > 63:
            return None
        results.append(common.chr(l))
        results.append(label)
    results.append(b'\0')
    return b''.join(results)

#构造请求报文
def build_request(address, qtype):
    request_id = os.urandom(2)
    header = struct.pack('!BBHHHH', 1, 0, 1, 0, 0, 0)
    addr = build_address(address)
    qtype_qclass = struct.pack('!HH', qtype, QCLASS_IN)
    return request_id + header + addr + qtype_qclass


def parse_ip(addrtype, data, length, offset):
    if addrtype == QTYPE_A:
        return socket.inet_ntop(socket.AF_INET, data[offset:offset + length])
    elif addrtype == QTYPE_AAAA:
        return socket.inet_ntop(socket.AF_INET6, data[offset:offset + length])
    elif addrtype in [QTYPE_CNAME, QTYPE_NS]:
        return parse_name(data, offset)[1]
    else:
        return data[offset:offset + length]


def parse_name(data, offset):
    p = offset
    labels = []
    l = common.ord(data[p])
    while l > 0:
        if (l & (128 + 64)) == (128 + 64):
            # pointer
            pointer = struct.unpack('!H', data[p:p + 2])[0]
            pointer &= 0x3FFF
            r = parse_name(data, pointer)
            labels.append(r[1])
            p += 2
            # pointer is the end
            return p - offset, b'.'.join(labels)
        else:
            labels.append(data[p + 1:p + 1 + l])
            p += 1 + l
        l = common.ord(data[p])
    return p - offset + 1, b'.'.join(labels)


# rfc1035
# record
#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
def parse_record(data, offset, question=False):
    nlen, name = parse_name(data, offset)
    if not question:
        record_type, record_class, record_ttl, record_rdlength = struct.unpack(
            '!HHiH', data[offset + nlen:offset + nlen + 10]
        )
        ip = parse_ip(record_type, data, record_rdlength, offset + nlen + 10)
        return nlen + 10 + record_rdlength, \
            (name, ip, record_type, record_class, record_ttl)
    else:
        record_type, record_class = struct.unpack(
            '!HH', data[offset + nlen:offset + nlen + 4]
        )
        return nlen + 4, (name, None, record_type, record_class, None, None)

#解析dns数据头
def parse_header(data):
    if len(data) >= 12:
        header = struct.unpack('!HBBHHHH', data[:12])
        #ID: 2个字节(16bit)，标识字段，客户端会解析服务器返回的DNS应答报文，
        #获取ID值与请求报文设置的ID值做比较，如果相同，则认为是同一个DNS会话
        res_id = header[0]
        #后面的两个字节（BB）是flags
        #QR: 0表示查询报文，1表示响应报文;
        res_qr = header[1] & 128
        # TC 截断(TrunCation) - 用来指出报文比允许的长度还要长，导致被截断。
        res_tc = header[1] & 2
        # RA      支持递归(Recursion Available) - 这个比特位在应答中设置
        # 或取消，用来代表服务器是否支持递归查询。
        res_ra = header[2] & 128
        #RCODE   应答码(Response code) - 这4个比特位在应答报文中设置，代表的含义如下：
        #        0               没有错误。
        #        1               报文格式错误(Format error) - 服务器不能理解请求的报文。
        #        2               服务器失败(Server failure) - 因为服务器的原因导致没办法处理这个请求。
        #        3               名字错误(Name Error) - 只有对授权域名解析服务器有意义，指出解析的域名不存在。
        #        4               没有实现(Not Implemented) - 域名服务器不支持查询类型。
        #        5               拒绝(Refused) - 服务器由于设置的策略拒绝给出应答。比如，服务器不希望对某些请求者给出应答，
        #                        或者服务器不希望进行某些操作（比如区域传送zone transfer）。
        #        6-15            保留值，暂时未使用。
        res_rcode = header[2] & 15
        # assert res_tc == 0
        # assert res_rcode in [0, 3]
        # QDCOUNT 无符号16位整数表示报文请求段中的问题记录数。
        res_qdcount = header[3]
        # ANCOUNT 无符号16位整数表示报文回答段中的回答记录数。
        res_ancount = header[4]
        # NSCOUNT 无符号16位整数表示报文授权段中的授权记录数。
        res_nscount = header[5]
        # ARCOUNT 无符号16位整数表示报文附加段中的附加记录数。
        res_arcount = header[6]
        return (res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount,
                res_ancount, res_nscount, res_arcount)
    return None


#解析dns响应报文
def parse_response(data):
    try:
        if len(data) >= 12:
            header = parse_header(data)
            if not header:
                #解析失败
                return None
            res_id, res_qr, res_tc, res_ra, res_rcode, res_qdcount, \
                res_ancount, res_nscount, res_arcount = header

            qds = []
            ans = []
            offset = 12
            #遍历请求段中的所有问题
            for i in range(0, res_qdcount):
                l, r = parse_record(data, offset, True)
                offset += l
                if r:
                    qds.append(r)
            #遍历响应段的所有回答
            for i in range(0, res_ancount):
                l, r = parse_record(data, offset)
                offset += l
                if r:
                    ans.append(r)
            #遍历所有ns回答
            for i in range(0, res_nscount):
                l, r = parse_record(data, offset)
                offset += l
            #遍历所有权威记录
            for i in range(0, res_arcount):
                l, r = parse_record(data, offset)
                offset += l
            response = DNSResponse()
            if qds:
                response.hostname = qds[0][0]
            for an in qds:
                response.questions.append((an[1], an[2], an[3]))
            for an in ans:
                response.answers.append((an[1], an[2], an[3]))
            return response
    except Exception as e:
        shell.print_exception(e)
        return None


def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == b'.':
        hostname = hostname[:-1]
    return all(VALID_HOSTNAME.match(x) for x in hostname.split(b'.'))


class DNSResponse(object):
    def __init__(self):
        self.hostname = None
        self.questions = []  # each: (addr, type, class)
        self.answers = []  # each: (addr, type, class)

    def __str__(self):
        return '%s: %s' % (self.hostname, str(self.answers))


STATUS_FIRST = 0
STATUS_SECOND = 1


class DNSResolver(object):

    def __init__(self, server_list=None, prefer_ipv6=False):
        self._loop = None
        #记录/etc/hosts中已定义的本地dns名称
        self._hosts = {}
        self._hostname_status = {}
        self._hostname_to_cb = {}
        self._cb_to_hostname = {}
        self._cache = lru_cache.LRUCache(timeout=300)
        self._sock = None
        if server_list is None:
            #记录dns服务器地址（来源于/etc/resolv.conf)
            self._servers = None
            self._parse_resolv()
        else:
            #用户指定了dns server地址（数组类型）
            self._servers = server_list
        if prefer_ipv6:
            #如果优先选择ipv6地址，则将地址类型更改为4A记录
            self._QTYPES = [QTYPE_AAAA, QTYPE_A]
        else:
            #优先选择ipv4地址
            self._QTYPES = [QTYPE_A, QTYPE_AAAA]
        self._parse_hosts()
        # TODO monitor hosts change and reload hosts
        # TODO parse /etc/gai.conf and follow its rules

    #设置dns server地址
    def _parse_resolv(self):
        self._servers = []
        try:
            with open('/etc/resolv.conf', 'rb') as f:
                content = f.readlines()
                for line in content:
                    line = line.strip()
                    if not (line and line.startswith(b'nameserver')):
                        continue
                    #在resolv.conf中找到一行数据，且此行以nameserver开头
                    #将此行数据按‘ ’划分，接受两项分隔结果
                    parts = line.split()
                    if len(parts) < 2:
                        continue
                    #添加dns服务器地址
                    server = parts[1]
                    if common.is_ip(server) == socket.AF_INET:
                        if type(server) != str:
                            server = server.decode('utf8')
                        self._servers.append(server)
        except IOError:
            pass
        if not self._servers:
            #如果未在resolv.conf中发现有效地址，则使用google dns地址
            self._servers = ['8.8.4.4', '8.8.8.8']

    #通过解析/etc/hosts得用户配置的主机名称
    def _parse_hosts(self):
        #取hosts配置
        etc_path = '/etc/hosts'
        if 'WINDIR' in os.environ:
            etc_path = os.environ['WINDIR'] + '/system32/drivers/etc/hosts'
        try:
            with open(etc_path, 'rb') as f:
                for line in f.readlines():
                    line = line.strip()
                    parts = line.split()
                    if len(parts) < 2:
                        continue #小于两项的不考虑

                    ip = parts[0]
                    if not common.is_ip(ip):
                        continue #非ip地址的不考虑

                    #记录hostname对应的主机的ip地址
                    for i in range(1, len(parts)):
                        hostname = parts[i]
                        if hostname:
                            self._hosts[hostname] = ip
        except IOError:
            #填写localhost主机为127.0.0.1
            self._hosts['localhost'] = '127.0.0.1'

    #将自身注册至loop中
    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        # TODO when dns server is IPv6
        # 开一个udp socket,设置为非阻塞
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                   socket.SOL_UDP)
        self._sock.setblocking(False)
        
        #在loop中注册自已的socket,注册周期性事务
        loop.add(self._sock, eventloop.POLL_IN, self)
        loop.add_periodic(self.handle_periodic)

    #拿到ip，或者没有拿到ip时，执行此回调
    def _call_callback(self, hostname, ip, error=None):
        callbacks = self._hostname_to_cb.get(hostname, [])
        for callback in callbacks:
            if callback in self._cb_to_hostname:
                del self._cb_to_hostname[callback]
            if ip or error:
                callback((hostname, ip), error)
            else:
                callback((hostname, None),
                         Exception('unknown hostname %s' % hostname))
        if hostname in self._hostname_to_cb:
            del self._hostname_to_cb[hostname]
        if hostname in self._hostname_status:
            del self._hostname_status[hostname]

    #处理dns响应
    def _handle_data(self, data):
        response = parse_response(data)
        if response and response.hostname:
            hostname = response.hostname
            ip = None
            for answer in response.answers:
                if answer[1] in (QTYPE_A, QTYPE_AAAA) and \
                        answer[2] == QCLASS_IN:
                    ip = answer[0] #返回ip地址
                    break
            if not ip and self._hostname_status.get(hostname, STATUS_SECOND) \
                    == STATUS_FIRST:
                #没有找到ip地址，且为首次请求，则请求下一类型（a记录，4a记录）
                self._hostname_status[hostname] = STATUS_SECOND
                self._send_req(hostname, self._QTYPES[1])
            else:
                if ip:
                    #请求到ip,将ip加入到缓存中
                    self._cache[hostname] = ip
                    #执行拿到ip地址的回调
                    self._call_callback(hostname, ip)
                elif self._hostname_status.get(hostname, None) \
                        == STATUS_SECOND:
                    #发送了两次请求，仍没有拿到ip地址
                    for question in response.questions:
                        if question[1] == self._QTYPES[1]:
                            #执行没有拿到ip地址的回调
                            self._call_callback(hostname, None)
                            break

    #sock有数据来
    def handle_event(self, sock, fd, event):
        if sock != self._sock:
            return #非自身socket,可能存在bug，不处理
        if event & eventloop.POLL_ERR:
            #socket发生错误，重新打开socket
            logging.error('dns socket err')
            self._loop.remove(self._sock)
            self._sock.close()
            # TODO when dns server is IPv6
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM,
                                       socket.SOL_UDP)
            self._sock.setblocking(False)
            self._loop.add(self._sock, eventloop.POLL_IN, self)
        else:
            #自socket中读取数据
            data, addr = sock.recvfrom(1024)
            #收到非指定server的报文，丢弃
            if addr[0] not in self._servers:
                logging.warn('received a packet other than our dns')
                return
            self._handle_data(data)

    def handle_periodic(self):
        self._cache.sweep()

    def remove_callback(self, callback):
        hostname = self._cb_to_hostname.get(callback)
        if hostname:
            del self._cb_to_hostname[callback]
            arr = self._hostname_to_cb.get(hostname, None)
            if arr:
                arr.remove(callback)
                if not arr:
                    del self._hostname_to_cb[hostname]
                    if hostname in self._hostname_status:
                        del self._hostname_status[hostname]

    #发送dns请求
    def _send_req(self, hostname, qtype):
        #构造请求，并发送，给server的53号端口
        req = build_request(hostname, qtype)
        for server in self._servers:
            logging.debug('resolving %s with type %d using server %s',
                          hostname, qtype, server)
            self._sock.sendto(req, (server, 53))

    def resolve(self, hostname, callback):
        if type(hostname) != bytes:
            hostname = hostname.encode('utf8')
        if not hostname:
            callback(None, Exception('empty hostname'))
        elif common.is_ip(hostname):
            callback((hostname, hostname), None)
        elif hostname in self._hosts:
            logging.debug('hit hosts: %s', hostname)
            ip = self._hosts[hostname]
            callback((hostname, ip), None)
        elif hostname in self._cache:
            logging.debug('hit cache: %s', hostname)
            ip = self._cache[hostname]
            callback((hostname, ip), None)
        else:
            if not is_valid_hostname(hostname):
                callback(None, Exception('invalid hostname: %s' % hostname))
                return
            arr = self._hostname_to_cb.get(hostname, None)
            if not arr:
                self._hostname_status[hostname] = STATUS_FIRST
                self._send_req(hostname, self._QTYPES[0])
                self._hostname_to_cb[hostname] = [callback]
                self._cb_to_hostname[callback] = hostname
            else:
                arr.append(callback)
                # TODO send again only if waited too long
                self._send_req(hostname, self._QTYPES[0])

    def close(self):
        if self._sock:
            if self._loop:
                self._loop.remove_periodic(self.handle_periodic)
                self._loop.remove(self._sock)
            self._sock.close()
            self._sock = None


def test():
    dns_resolver = DNSResolver()
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop)

    global counter
    counter = 0

    def make_callback():
        global counter

        def callback(result, error):
            global counter
            # TODO: what can we assert?
            print(result, error)
            counter += 1
            if counter == 9:
                dns_resolver.close()
                loop.stop()
        a_callback = callback
        return a_callback

    assert(make_callback() != make_callback())

    dns_resolver.resolve(b'google.com', make_callback())
    dns_resolver.resolve('google.com', make_callback())
    dns_resolver.resolve('example.com', make_callback())
    dns_resolver.resolve('ipv6.google.com', make_callback())
    dns_resolver.resolve('www.facebook.com', make_callback())
    dns_resolver.resolve('ns2.google.com', make_callback())
    dns_resolver.resolve('invalid.@!#$%^&$@.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())
    dns_resolver.resolve('toooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'ooooooooooooooooooooooooooooooooooooooooooooooooooo'
                         'long.hostname', make_callback())

    loop.run()


if __name__ == '__main__':
    test()
