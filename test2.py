from time import sleep, time
from struct import pack, unpack
import socket
from random import choices
from icmplib.exceptions import ICMPSocketError, TimeoutExceeded
from icmplib.utils import unique_identifier

def ttlicmp(ip, count = 3, interval = 0.5, timeout = 0.5, ttl = 30):
    icmpsocket =  socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMP)
    
    replies = []
    id = unique_identifier()
        
    for sequence in range(count):
        if sequence > 0:
            sleep(interval)

        try:
            send(ip,id, sequence, icmpsocket, ttl)
            reply = None
            reply = receive(timeout, id, sequence, icmpsocket)
            
        except Exception as e:
            print(e)

        replies.append(reply)
    
    for reply in replies:
        if reply:
            return reply

def send(ip, id, sequence, icmpsocket : socket.socket, ttl):
    packet = create_packet(id, sequence)
    icmpsocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL,ttl)
    target = socket.getaddrinfo(ip, port=None, family= icmpsocket.family, type=icmpsocket.type)[0][4]
    icmpsocket.sendto(packet, target)

def receive(timeout, id, sequence, icmpsocket : socket.socket):
    icmpsocket.settimeout(timeout)
    time_limit = time() + timeout

    try:
        while True:
            response = icmpsocket.recvfrom(1024)
            current_time = time()

            source = response[1][0]

            if current_time > time_limit:
                raise socket.timeout
            responseid, responsesequence = unpack('!2H', response[0][24:28])
            if (response and id == responseid and sequence == responsesequence):
                return source

    except socket.timeout:
        raise TimeoutExceeded(timeout)

    except OSError as err:
        raise ICMPSocketError(str(err))

def create_packet(id, sequence):
    checksum = 0
    payload = bytes(choices(b'abcdefghijklmnopqrstuvwxyz' b'ABCDEFGHIJKLMNOPQRSTUVWXYZ'b'1234567890', k=56))
            
    header = pack('!2B3H', 8, 0, checksum, id, sequence)
    checksum = calculatechecksum(header + payload)
    header = pack('!2B3H', 8, 0, checksum, id, sequence)
    return header + payload

def calculatechecksum(data):
        '''
        Compute the checksum of an ICMP packet. Checksums are used to
        verify the integrity of packets.

        '''
        sum = 0
        data += b'\x00'

        for i in range(0, len(data) - 1, 2):
            sum += (data[i] << 8) + data[i + 1]
            sum  = (sum & 0xffff) + (sum >> 16)

        sum = ~sum & 0xffff

        return sum

host = ttlicmp("1.1.1.1", ttl= 3)

print(host)