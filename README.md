dnsproxy
========

dnsproxy is a simple DNS proxy server, supporting wilcard hosts, IPv6 and cache.


Usage
=====

Edit /etc/hosts, add:

    127.0.0.1 *.local
    2404:6800:8005::62 *.blogspot.com

startup dnsproxy (using OpenDNS as an example):

    $ sudo python dnsproxy.py -s 208.67.222.222

Set the system DNS server as 127.0.0.1, you can verify it by dig or nslookup:

    $ dig test.local

The result should contain 127.0.0.1.


License
=======

dnsproxy was first developed and released by marlonyao<yaolei135@gmail.com> under the BSD 3-Clause license (see LICENSE.bsd). The first commit in this repository is his original source and thus BSD-licensed. All later commits are released under the GPLv3 (see LICENSE.gpl).
