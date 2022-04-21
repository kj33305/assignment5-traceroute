from socket import *
import os
import sys
import struct
import time
import select
import binascii


ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1
# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    #Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    dummyChecksum = 0
    header = struct.pack("bbHh", ICMP_ECHO_REQUEST, 0, dummyChecksum, 1)

    data = struct.pack("d", time.time())

    dummyChecksum = checksum(data + header)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, dummyChecksum, (os.getpid() & 0xFFFF), 1)
    #print(header)
    # Don’t send the packet yet , just return the final packet in this function.
    #Fill in end

    # So the function ending should look like this

    packet = header + data
    #print("Just made my packet")
    #print(packet)
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    tracelist1 = [] #This is your list to use when iterating through each trace 
    tracelist2 = [] #This is your list to contain all traces

    destAddr = gethostbyname(hostname)
    #print(destAddr)
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            #destAddr = gethostbyname(hostname)
            #print(destAddr)
            #Fill in start
            # Make a raw socket named mySocket
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            #Fill in end

            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                #print(t)
                startedSelect = time.time()
                #print(startedSelect)
                whatReady = select.select([mySocket], [], [], timeLeft)
                #print(whatReady)
                howLongInSelect = (time.time() - startedSelect)
                #print(howLongInSelect)
                #print("Just printed how long in select")

                if whatReady[0] == []: # Timeout
                    tracelist1.append("* * * Request timed out")
                    #print("TimedOut")
                    #Fill in start
                    #You should add the list above to your all traces list
                    tracelist2.append([str(ttl), tracelist1[-1]])
                    #print("Added to tracelist2")
                    #print(tracelist2)
                    tracelist1.clear()
                    #print("tracelist2 cleared")
                    #print("Request timed out")
                    # print('test')
                    #Fill in end
                    #print("On to packet stuff...")
                recvPacket, addr = mySocket.recvfrom(1024)

                #print("Now I will get time received")
                timeReceived = time.time()
                #print("Getting time received next")
                #print(timeReceived)
                timeLeft = timeLeft - howLongInSelect
                #print(timeLeft)
                if timeLeft <= 0:
                    tracelist1.append("* * * Request timed out.")
                    # Fill in start
                    # You should add the list above to your all traces list
                    tracelist2.append([str(ttl), tracelist1[-1]])

                    tracelist1.clear()
                    # print("Request timed out")
                    #print("cleared tracelist")
                    # Fill in end
            except timeout:
                #print("Timed out and ready to continue")
                continue
                #print("continue")

            else:
                #Fill in start
                #Fetch the icmp type from the IP packet

                #icmp_header = recPacket[20:28]
                #type, icmp_code, checksum, packet_id, sequence_no = struct.unpack("bbHHh", icmp_header)

                icmp_Type, icmp_Code, icmp_Checksum, icmp_ID, icmp_Sequence, timeSent = struct.unpack("bbHHhd",
                                                                                                      recvPacket[20:36])
                types = struct.unpack("b", recvPacket[20:21])

                #print("Fetched icmpHeader")

                #Fill in end
                try: #try to fetch the hostname
                    #Fill in start
                    hostName = gethostbyaddr(addr[0])[0]
                    #print(hostName)
                    #Fill in end
                except herror: #if the host does not provide a hostname
                    #Fill in start
                    #print("Unable to provide hostname")
                    hostName = "Unable to provide hostname"
                    #Fill in end
                if types == 11:
                    #print("Type 11 time Exceeded")
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should add your responses to your lists here

                    #mytimeSent = struct.unpack("d", recvPacket[28:36])[0]
                    tracelist1.append([str(ttl), str(round((timeReceived - mytimeSent) * 1000)) + "ms", str(addr[0]),
                                       hostName])
                    tracelist2.append(tracelist1)

                    tracelist1.clear()
                    # print("  %d rtt=%.0f ms %s" % (ttl, (timeReceived - t) * 1000, addr[0]))
                    #Fill in end
                elif types == 3:
                    #print("Type 3 Destination unreachable")
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should add your responses to your lists here

                    #tracelist1.append([str(ttl), str(round((timeReceived - mytimeSent) * 1000)) + "ms", addr[0]])
                    tracelist1.append([str(ttl), '*', 'Request timed out'])

                    tracelist2.append(tracelist1)

                    tracelist1.clear()
                    #print("  %d rtt=%.0f ms %s" % (ttl, (timeReceived - t) * 1000, addr[0]))
                    #Fill in end
                elif types == 0:
                    #print("Type 0 Echo reply")
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    #Fill in start
                    #You should add your responses to your lists here and return your list if your destination IP is met

                    #mytimeSent = struct.unpack("d", recvPacket[28:36])[0]
                    tracelist1.append([str(ttl), str(round((timeReceived - timeSent) * 1000)) + "ms", str(addr[0]),
                                       hostName])
                    #tracelist1.append([str(ttl), str(round((timeReceived - mytimeSent) * 1000)) + "ms", gethostbyaddr(destAddr[0])])
                    tracelist2.append(tracelist1)

                    tracelist1.clear()
                    #print("  %d rtt=%.0f ms %s" % (ttl, (timeReceived - timeSent) * 1000, addr[0]))
                    return tracelist2
                    #Fill in end
                else:
                    #Fill in start
                    #If there is an exception/error to your if statements, you should append that to your list here
                    #print("Error")
                    tracelist1.append([ttl, "*", "Error received"])
                    #Fill in end
                break
            finally:
                mySocket.close()
        return tracelist2

if __name__ == '__main__':
    get_route("google.com")