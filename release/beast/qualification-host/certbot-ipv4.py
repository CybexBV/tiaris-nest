#!/usr/bin/python3
"""Use the server's authorized IPv4 egress for DNS certificate validation."""
import socket
import sys
from certbot.main import main

original_getaddrinfo = socket.getaddrinfo


def ipv4_getaddrinfo(host, port, family=0, *args, **kwargs):
    return original_getaddrinfo(host, port, socket.AF_INET if family == socket.AF_UNSPEC else family, *args, **kwargs)


socket.getaddrinfo = ipv4_getaddrinfo
sys.exit(main())
