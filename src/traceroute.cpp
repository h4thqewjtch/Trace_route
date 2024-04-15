#include "traceroute.h"

std::map<int, std::string> icmpMessageTypesMap{
    {0, "ECHO REPLY"},
    {3, "DESTINATION UNREACHABLE"},
    {4, "SOURCE QUENCH"},
    {5, "REDIRECT"},
    {6, "ALTERNATIVE HOST ADDRESS"},
    {8, "ECHO"},
    {9, "ROUTER ADVERTISEMENT"},
    {10, "ROUTER SOLICITATION"},
    {11, "TIME EXCEEDED"},
    {12, "PARAMETER PROBLEM"},
    {13, "TIMESTAMP"},
    {14, "TIMESTAMP REPLY"}};

std::map<int, std::string> icmpMessageCodesMap{
    {0, "NET UNREACHABLE"},
    {1, "HOST UNREACHABLE"},
    {2, "PROTOCOL QUENCH"},
    {3, "PORT UNREACHABLE"},
    {4, "FRAGMENTATION NEEDED"},
    {5, "SOURCE ROUTE FAILED"},
    {6, "DESTINATION NETWORK UNKNOWN"},
    {7, "DESTINATION HOST UNKNOWN"},
    {8, "SOURCE HOST ISOLATED"},
    {9, "COMMUNICATION WITH DESTINATION NETWORK IS ADMINISTRATIVELY PROHIBITED"},
    {10, "COMMUNICATION WITH DESTINATION HOST IS ADMINISTRATIVELY PROHIBITED"},
    {11, "DESTINATION NETWORK UNREACHABLE FOR TYPE OF SERVICE"},
    {12, "DESTINATION HOST UNREACHABLE FOR TYPE OF SERVICE"},
    {13, "COMMUNICATION ADMINISTRATIVELY PROHIBITED"},
    {14, "HOST PRECEDENCE VIOLATION"},
    {15, "PRECEDENCE CUTOFF IN EFFECT"}};

void check_command_line_arguments(int argc)
{
    if (argc < 2)
    {
        throw LocalException("Destination address does not exist");
    }
}

void wsa_startup(WSADATA &wsaData)
{
    if (WSAStartup(MAKEWORD(2, 2), &wsaData))
    {
        throw LocalException("WSAStartup() in wsa_startup() failed with error " + std::to_string(WSAGetLastError()));
    }
}

void create_socket(SOCKET &socket)
{
    socket = WSASocket(AF_INET,
                       SOCK_RAW,
                       IPPROTO_ICMP,
                       NULL,
                       0,
                       WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET)
    {
        throw LocalException("WSASocket() in create_socket() failed with error " + std::to_string(WSAGetLastError()));
    }
}

void set_socket_timeout(SOCKET socket, int timeout, int timeoutType)
{
    int setsockoptReturnValue = setsockopt(socket,
                                           SOL_SOCKET,
                                           timeoutType,
                                           (char *)&timeout,
                                           sizeof(timeout));
    if (setsockoptReturnValue == SOCKET_ERROR)
    {
        throw LocalException("setsockopt() in set_socket_timeout() failed with error " + std::to_string(WSAGetLastError()));
    }
}

void set_destination_address(SOCKADDR_IN &destinationAddress, char *hostName)
{
    ZeroMemory(&destinationAddress, sizeof(destinationAddress));
    destinationAddress.sin_family = AF_INET;
    if ((destinationAddress.sin_addr.s_addr = inet_addr(hostName)) == INADDR_NONE)
    {
        HOSTENT *hostInfo = gethostbyname(hostName);
        if (hostInfo)
            memcpy(&(destinationAddress.sin_addr), hostInfo->h_addr, hostInfo->h_length);
        else
        {
            throw LocalException("gethostbyname() in set_destination_address() failed with error " + std::to_string(WSAGetLastError()));
        }
    }
}

void set_socket_routing(SOCKET socket)
{
    //  to bypass the standard routing mechanisms

    BOOL optVal = TRUE;
    int setsockoptReturnValue = setsockopt(socket,
                                           SOL_SOCKET,
                                           SO_DONTROUTE,
                                           (char *)&optVal,
                                           sizeof(BOOL));
    if (setsockoptReturnValue == SOCKET_ERROR)
    {
        throw LocalException("setsockopt() in set_socket_routing() failed with error " + std::to_string(WSAGetLastError()));
    }
}

void trace_route(SOCKET &socket, SOCKADDR_IN &destinationAddress)
{
    char requestPacket[1024]{}, responsePacket[1024]{};
    int quit = 0, seqNumber = 0;
    int dataSize = sizeof(ICMPHeader);
    SOCKADDR_IN sourceAddress;
    for (int timeToLive = 1; timeToLive <= 50 && !quit; timeToLive++)
    {
        set_time_to_live(socket, timeToLive);
        set_request_packet(requestPacket, dataSize, seqNumber);
        seqNumber++;
        int sentBytes = send_request_packet(socket,
                                            requestPacket,
                                            dataSize,
                                            destinationAddress);
        if (sentBytes == -2)
        {
            std::cout << std::setw(2) << timeToLive
                      << "\ttime to send packet has been exceeded" << std::endl;
            continue;
        }
        int receivedBytes = receive_response_packet(socket,
                                                    responsePacket,
                                                    1024,
                                                    sourceAddress);
        if (receivedBytes == -2)
        {
            std::cout << std::setw(2) << timeToLive
                      << "\ttime to receive packet has been exceeded" << std::endl;
            continue;
        }
        quit = parse_response_packet(responsePacket, receivedBytes, &sourceAddress, timeToLive);
        Sleep(1000);
    }
}

void set_time_to_live(SOCKET socket, int timeToLive)
{
    int setsockoptReturnValue = setsockopt(socket,
                                           IPPROTO_IP,
                                           IP_TTL,
                                           (LPSTR)&timeToLive,
                                           sizeof(timeToLive));
    if (setsockoptReturnValue == SOCKET_ERROR)
    {
        throw LocalException("setsockopt() in set_time_to_live() failed with error " + std::to_string(WSAGetLastError()));
    }
}

void set_request_packet(char *requestPacket, int dataSize, int sequenceNumber)
{
    ICMPHeader *icmpHeader = (ICMPHeader *)requestPacket;
    icmpHeader->messageType = 8;
    icmpHeader->messageCode = 0;
    icmpHeader->identificator = (USHORT)GetCurrentProcessId();
    icmpHeader->messageCheckSum = 0;
    icmpHeader->sequenceNumber = sequenceNumber;
    icmpHeader->messageCheckSum = calculate_check_sum((USHORT *)requestPacket,
                                                      dataSize);
}

USHORT calculate_check_sum(USHORT *data, int dataSize)
{
    ULONG checkSum = 0;
    while (dataSize > 1)
    {
        checkSum += *data++;
        dataSize -= sizeof(unsigned short);
    }
    if (dataSize)
    {
        checkSum += *(unsigned char *)data;
    }
    checkSum = (checkSum >> 16) + (checkSum & 0xffff);
    checkSum += (checkSum >> 16);
    return (USHORT)(~checkSum);
}

int send_request_packet(SOCKET &socket, char *requestPacket, int dataSize, SOCKADDR_IN &addressTo)
{
    int sentBytes = sendto(socket,
                           requestPacket,
                           dataSize,
                           0,
                           (SOCKADDR *)&addressTo,
                           sizeof(addressTo));
    if (sentBytes == SOCKET_ERROR)
    {
        if (WSAGetLastError() == WSAETIMEDOUT)
        {
            return -2;
        }
        throw LocalException("sendto() failed with error " + std::to_string(WSAGetLastError()));
    }
    return sentBytes;
}

int receive_response_packet(SOCKET &socket, char *responsePacket, int dataSize, SOCKADDR_IN &addressFrom)
{
    int addressFromSize = sizeof(addressFrom);
    int receivedBytes = recvfrom(socket,
                                 responsePacket,
                                 dataSize,
                                 0,
                                 (struct sockaddr *)&addressFrom,
                                 &addressFromSize);
    if (receivedBytes == SOCKET_ERROR)
    {
        if (WSAGetLastError() == WSAETIMEDOUT)
        {
            return -2;
        }
        throw LocalException("recvfrom() failed with error " + std::to_string(WSAGetLastError()));
    }
    return receivedBytes;
}

int parse_response_packet(char *responsePacket, int receivedBytes, SOCKADDR_IN *addressFrom, int timeToLive)
{
    IPHeader *ipHeader = (IPHeader *)responsePacket;
    USHORT ipHeaderLength = ipHeader->headerLength * 4;
    ICMPHeader *icmpHeader = (ICMPHeader *)(responsePacket + ipHeaderLength);
    std::string responseAddress = std::string(inet_ntoa(addressFrom->sin_addr));
    int returnValue = 1;
    std::cout << std::setw(2) << timeToLive << "\t";
    if (icmpHeader->messageType == 0)
    {
        std::cout << responseAddress << " - destination address" << std::endl;
    }
    else if (icmpHeader->messageType == 11)
    {
        std::cout << responseAddress << std::endl;
        returnValue = 0;
    }
    else
    {
        int messageType = static_cast<int>(icmpHeader->messageType);
        int messageCode = static_cast<int>(icmpHeader->messageCode);
        std::cout << responseAddress << std::endl
                  << "ICMP Message Type: " << messageType
                  << "\t" << icmpMessageTypesMap[messageType] << std::endl
                  << "ICMP Message Code: " << messageCode
                  << "\t" << icmpMessageCodesMap[messageCode] << std::endl;
    }
    return returnValue;
}
