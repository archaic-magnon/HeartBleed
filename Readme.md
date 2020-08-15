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