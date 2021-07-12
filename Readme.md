# HeartBleed

The Heartbleed bug (CVE-2014-0160) is a severe implementation flaw in the
OpenSSL library, which enables attackers to steal data from the memory of
the victim server. The contents of the stolen data depend on what is there
in the memory of the server. It could potentially contain private keys, TLS
session keys, user names, passwords, credit cards, etc. The vulnerability is in
the implementation of the Heartbeat protocol, which is used by SSL/TLS to
keep the connection alive. (See Report for more details)


## How to run
1. Run server.py 
```python3 server.py```

2. On new tab run client.py
```python3 client.py```

Terminal output of client and server will show what is happening on the background.



My code for heart bleed vulnerabilities consists of 3 files
1. SSLPacket.py 
	It have python class associated with the SSL packet.  It defines the structure of the SSL packet and the field associated with packet. It also defined the possible values of the some field in the packet

2. Server.py
	This files consist of the functionalities of SSL server.  The main functionality used in this demo is the heartbeat.  Server responds with the clients heartbeat request.

3. Client.py
	This  file  consists  of  file  associated  the  client.   For  this  demo clients main functionality is the sending heartbeat request to the server.
