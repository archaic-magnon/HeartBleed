import socket
from SSLPacket import SSLPacket, H_BEAT, H_SHAKE, C_HELLO, S_HELLO, CERT, S_KEY_EX, CERT_REQ, S_HELLO_FIN, CERT_VERIFY, C_KEY_EX, FIN, END
import time

HOST = '127.0.0.1' # Standard loopback interface address (localhost)
PORT = 65432 # Port to listen on (non-privileged ports are > 1023)
BUFSIZE = 1024 # Buffer size 

end_conn = [False] # Flag for ending current connection


# Memory of server. 
# It may contain sensitive information like bank details, password

SERVER_MEMORY = ['0x55', '0x73', '0x65', '0x72', '0x4e', '0x61', '0x6d', 
    '0x65', '0x3d', '0x4a', '0x6f', '0x68', '0x6e', '0x2c', '0x20', '0x50', 
    '0x61', '0x73', '0x73', '0x77', '0x6f', '0x72', '0x64', '0x3d', '0x4a', 
    '0x6f', '0x68', '0x6e', '0x31', '0x32', '0x33', '0x2c', '0x20', '0x43', 
    '0x72', '0x65', '0x64', '0x69', '0x74', '0x43', '0x61', '0x72', '0x64', 
    '0x3d', '0x39', '0x38', '0x37', '0x35', '0x32', '0x31', '0x33', '0x34', 
    '0x35', '0x2c', '0x20', '0x42', '0x61', '0x6e', '0x6b', '0x50', '0x61', 
    '0x73', '0x73', '0x77', '0x6f', '0x72', '0x64', '0x3a', '0x6a', '0x40', 
    '0x23', '0x24', '0x74', '0x79', '0x2c', '0x20', '0x61', '0x64', '0x64', 
    '0x72', '0x3a', '0x4e', '0x65', '0x77', '0x20', '0x44', '0x65', '0x6c', 
    '0x68', '0x69', '0x2c', '0x20', '0x66', '0x62', '0x50', '0x61', '0x73', 
    '0x73', '0x3d', '0x72', '0x65', '0x66', '0x77', '0x23', '0x34', '0x72', 
    '0x64', '0x2c', '0x20', '0x55', '0x73', '0x65', '0x72', '0x4e', '0x61', 
    '0x6d', '0x65', '0x3d', '0x41', '0x6c', '0x65', '0x78', '0x2c', '0x20', 
    '0x70', '0x61', '0x73', '0x73', '0x77', '0x6f', '0x72', '0x64', '0x3d', 
    '0x41', '0x6c', '0x78', '0x40', '0x33', '0x34', '0x2c', '0x20', '0x64', 
    '0x6f', '0x62', '0x3d', '0x31', '0x32', '0x2d', '0x30', '0x32', '0x2d', 
    '0x31', '0x39', '0x39', '0x38']


ServerCertificate = ["59467652654594579045204704659026993676857669894610627246987714672178033708927731406873670588249136548334145999864507269024117336147786875117231988094232518662725742126199332911607399915004520384839135344869032321406805564195832768994725681968680236396330393936568180173857366855542841532763503770510552366791", "89884656073422915895057700854908702141394053788705763061024006528957088284272561165973222425782114499216516944853108016001952665800988750697342469736954984512196620150130148944801747172324100194862553218248547376575755999950004183245161208448963591717966203142399704030128667578243881849387894000435620686139"]


# convert string to  hexadecimal list
def stringToHex(s):
    return [hex(ord(ch)) for ch in s]


# convert hexadecimal list to string
def hexToString(h):
    return "".join([chr(int(el, 16)) for el in h])


# send hello packet to client
def sendHelloPacket(conn):
    hello_packet = SSLPacket(type=H_SHAKE, payload_type=S_HELLO)
    print("Sending Hello Packet to Client...")
    conn.send(hello_packet.encode())


# recieve hello packet from client
def recieveHelloPacket(packet):
    if packet.payload_type == C_HELLO:
        print("Recieved Hello Packet from Client")


# send server certificate to client
def sendCertificate(conn):
    print("Sending Certificate...")
    packet = SSLPacket(type=H_SHAKE, payload_type=S_KEY_EX, payload=ServerCertificate)
    conn.send(packet.encode())


# send hello done indicating, it has replied to hello packet of client
def sendHelloDone(conn):
    print("Sending Hello done...")
    packet = SSLPacket(type=H_SHAKE, payload_type=S_HELLO_FIN)
    conn.send(packet.encode())


# recieve client certificate 
def recieveClientCertificate(packet):
    if packet.payload_type == C_KEY_EX:
        print("Recieved cert Packet from Client")


# recieve client FIN packet 
def recieveClientFin(packet):
    if packet.payload_type == FIN:
        print("Recieved Client fin")


# send FIN packet to client indicaitng completion of handshake
def sendServerFin(conn):
    packet = SSLPacket(type=H_SHAKE, payload_type=FIN)
    conn.send(packet.encode())


# send heart beat to client in responnse to client heart beat
def sendHeartBeat(conn, length, data):
    print("sending heart beat...")
    payload = data
    packet = SSLPacket(type=H_BEAT, payload_type=H_BEAT, length=length, payload=payload)
    if len(data) < length:
        payload = data + hexToString(SERVER_MEMORY)[: length - len(data)]
        packet.payload = payload

    conn.send(packet.encode())


# server handles data according to content of packet
def handleData(conn, data):
    # print(data.decode())
    d = SSLPacket().decode(data)
    if d.type == None:
        return

    if d.type == H_SHAKE:

        if d.payload_type == C_HELLO:
            recieveHelloPacket(d)
            sendHelloPacket(conn)
            time.sleep(1)
            sendCertificate(conn)
            time.sleep(1)
            sendHelloDone(conn)

        elif d.payload_type == C_KEY_EX:
            print("Recieved Client Certificate")

        elif d.payload_type == FIN:
            print("HandShake finished")
            sendServerFin(conn)

    if d.type == H_BEAT:
        print("Recieved heart beat")
        sendHeartBeat(conn, d.length, d.payload)

    if d.type == END:
        end_conn[0] = True
        print("Ending connection")


# start server
def runServer():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print("Server is running...")
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            print("-" * 40)
            with conn:
                print('Connected to', addr)
                while True:
                    if end_conn[0]:
                        end_conn[0] = False
                        break
                    data = conn.recv(BUFSIZE)
                    handleData(conn, data)


if __name__ == "__main__":
    runServer()
