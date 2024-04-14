#include "traceroute.h"

int main(int argc, char **argv)
{

    if (check_command_line_arguments(argc) == -1)
    {
        return -1;
    }
    WSADATA wsaData;
    if (wsa_startup(wsaData) == -1)
    {
        return -1;
    }
    int hopsNumber = get_nodes_number(argc, argv);
    SOCKET socket;
    if (create_socket(socket) == -1)
    {
        WSACleanup();
        return -1;
    }
    if (set_socket_timeout(socket, 1000, SO_RCVTIMEO) == -1)
    {
        closesocket(socket);
        WSACleanup();
        return -1;
    }
    if (set_socket_timeout(socket, 1000, SO_SNDTIMEO) == -1)
    {
        closesocket(socket);
        WSACleanup();
        return -1;
    }
    SOCKADDR_IN destinationAddress;
    if (set_destination_address(destinationAddress, argv[1]) == -1)
    {
        closesocket(socket);
        WSACleanup();
        return -1;
    }
    if (set_socket_routing(socket) == -1) // to bypass the standard routing mechanisms
    {                               
        closesocket(socket);
        WSACleanup();
        return -1;
    }
    std::cout << std::endl
              << "Tracing route to " << argv[1]
              << " with a maximum number of hops " << hopsNumber
              << ":" << std::endl
              << std::endl;
    if (trace_route(socket, destinationAddress, hopsNumber) == -1)
    {
        std::cout << std::endl
                  << "Tracing route aborted" << std::endl
                  << std::endl;
    }
    else
    {
        std::cout << std::endl
                  << "Tracing route finished" << std::endl
                  << std::endl;
    }
    closesocket(socket);
    WSACleanup();
    return 0;
}

int check_command_line_arguments(int argc)
{
    if (argc < 2)
    {
        std::cout << "Destination address does not exist" << std::endl;
        return -1; // throw
    }
    return 0;
}

int wsa_startup(WSADATA &wsaData)
{
    if (WSAStartup(MAKEWORD(2, 2), &wsaData))
    {
        std::cout << "WSAStartup() in wsa_startup() failed with error " << WSAGetLastError() << std::endl;
        return -1; // throw
    }
    return 0;
}

int get_nodes_number(int argc, char **argv)
{
    int hopsNumber;
    if (argc < 3 || (hopsNumber = atoi(argv[2])) == 0)
    {
        hopsNumber = 50;
    }
    return hopsNumber;
}

int create_socket(SOCKET &socket)
{
    socket = WSASocket(AF_INET,
                       SOCK_RAW,
                       IPPROTO_ICMP,
                       NULL,
                       0,
                       WSA_FLAG_OVERLAPPED);
    if (socket == INVALID_SOCKET)
    {
        std::cout << "WSASocket() in create_socket() failed with error " << WSAGetLastError() << std::endl;
        return -1; // throw
    }
    return 0;
}

int set_socket_timeout(SOCKET socket, int timeout, int timeoutType)
{
    int setsockoptReturnValue = setsockopt(socket,
                                           SOL_SOCKET,
                                           timeoutType,
                                           (char *)&timeout,
                                           sizeof(timeout));
    if (setsockoptReturnValue == SOCKET_ERROR)
    {
        std::cout << "setsockopt() in set_socket_timeout() failed with error "
                  << WSAGetLastError() << std::endl;
        return -1; // throw
    }
    return 0;
}

int set_destination_address(SOCKADDR_IN &destinationAddress, char *hostName)
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
            std::cout << "gethostbyname() in set_destination_address() failed with error "
                      << WSAGetLastError() << std::endl;
            return -1; // throw
        }
    }
    return 0;
}

int set_socket_routing(SOCKET socket)
{
    //  Set the socket to bypass the standard routing mechanisms
    //  i.e. use the local protocol stack to the appropriate network interface

    BOOL optVal = TRUE;
    int setsockoptReturnValue = setsockopt(socket,
                                           SOL_SOCKET,
                                           SO_DONTROUTE,
                                           (char *)&optVal,
                                           sizeof(BOOL));
    if (setsockoptReturnValue == SOCKET_ERROR)
    {
        std::cout << "setsockopt() in set_socket_routing() failed with error "
                  << WSAGetLastError() << std::endl;
        return -1;
    }
    return 0;
}

int trace_route(SOCKET &socket, SOCKADDR_IN &destinationAddress, int hopsNumber)
{
    char sendBuffer[1024]{};
    char receiveBuffer[1024]{};
    // int dataSize = sizeof(ULONG) + sizeof(ICMPHeader);
    int dataSize = sizeof(ICMPHeader);
    int quit = 0, seqNumber = 0;
    SOCKADDR_IN sourceAddress;
    int sourceAddressLength = sizeof(sourceAddress);
    for (int timeToLive = 1; timeToLive <= hopsNumber && !quit; timeToLive++)
    {
        set_time_to_live(socket, timeToLive);
        set_send_buffer(sendBuffer, dataSize, seqNumber);
        seqNumber++;
        int sentBytes = send_packet(socket,
                                    sendBuffer,
                                    dataSize,
                                    destinationAddress);
        if (sentBytes == -2)
        {
            std::cout << std::setw(2) << timeToLive
                      << "\ttime to send packet has been exceeded" << std::endl;
            continue;
        }
        else if (sentBytes == -1)
        {
            std::cout << std::setw(2) << timeToLive
                      << "\tsendto() failed with error "
                      << WSAGetLastError()
                      << std::endl;
            return -1;
        }
        int receivedBytes = receive_packet(socket,
                                           receiveBuffer,
                                           1024,
                                           sourceAddress);
        if (receivedBytes == -2)
        {
            std::cout << std::setw(2) << timeToLive
                      << "\ttime to receive packet has been exceeded" << std::endl;
            continue;
        }
        else if (receivedBytes == -1)
        {
            std::cout << std::setw(2) << timeToLive
                      << "\trecvfrom() failed with error "
                      << WSAGetLastError()
                      << std::endl;
            return -1;
        }
        quit = parse_response(receiveBuffer, receivedBytes, &sourceAddress, timeToLive);
        Sleep(1000);
    }
    return 0;
}

int set_time_to_live(SOCKET socket, int timeToLive)
{
    int setsockoptReturnValue = setsockopt(socket,
                                           IPPROTO_IP,
                                           IP_TTL,
                                           (LPSTR)&timeToLive,
                                           sizeof(timeToLive));
    if (setsockoptReturnValue == SOCKET_ERROR)
    {
        std::cout << std::setw(2) << timeToLive
                  << "\tsetsockopt() in set_time_to_live() failed with error "
                  << WSAGetLastError() << std::endl;
        return -1;
    }
    return 0;
}

void set_send_buffer(char *sendBuffer, int dataSize, int seqNumber)
{
    ICMPHeader *icmpHeader = (ICMPHeader *)sendBuffer;
    icmpHeader->messageType = 8;
    icmpHeader->messageCode = 0;
    icmpHeader->identificator = (USHORT)GetCurrentProcessId();
    icmpHeader->messageCheckSum = 0;
    icmpHeader->sequenceNumber = seqNumber;
    icmpHeader->messageCheckSum = calculate_check_sum((USHORT *)sendBuffer,
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

int send_packet(SOCKET &socket, char *sendBuffer, int dataSize, SOCKADDR_IN &addressTo)
{
    int sentBytes = sendto(socket,
                           sendBuffer,
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
        return -1;
    }
    return sentBytes;
}

int receive_packet(SOCKET &socket, char *receiveBuffer, int dataSize, SOCKADDR_IN &addressFrom)
{
    int addressFromSize = sizeof(addressFrom);
    int receivedBytes = recvfrom(socket,
                                 receiveBuffer,
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
        return -1;
    }
    return receivedBytes;
}

int parse_response(char *response, int receivedBytes, SOCKADDR_IN *addressFrom, int timeToLive)
{
    IPHeader *ipHeader = (IPHeader *)response;
    USHORT ipHeaderLength = ipHeader->headerLength * 4;
    ICMPHeader *icmpHeader = (ICMPHeader *)(response + ipHeaderLength);
    int returnValue = 1;
    struct hostent *hostInfo = gethostbyaddr((const char *)&addressFrom->sin_addr,
                                             AF_INET,
                                             sizeof(addressFrom->sin_addr));
    std::cout << std::setw(2) << timeToLive << "\t";
    if (icmpHeader->messageType == 0)
    {
        print_host_name_addr(hostInfo, addressFrom);
        std::cout << " - destination address" << std::endl;
    }
    else if (icmpHeader->messageType == 11)
    {
        print_host_name_addr(hostInfo, addressFrom);
        std::cout << std::endl;
        returnValue = 0;
    }
    else
    {
        std::cout << "ICMP Message Type: " << icmpHeader->messageType << std::endl
                  << "\t\t" << icmpMessageTypesMap[icmpHeader->messageType] << std::endl
                  << "\tICMP Message Code: " << icmpHeader->messageCode << std::endl
                  << "\t\t" << icmpMessageCodesMap[icmpHeader->messageCode] << std::endl;
    }
    return returnValue;
}

void print_host_name_addr(hostent* hostInfo, SOCKADDR_IN* addressFrom)
{
    if (hostInfo != NULL)
    {

        std::cout << hostInfo->h_name << " [" << inet_ntoa(addressFrom->sin_addr) << "]";
    }
    else
    {
        std::cout << inet_ntoa(addressFrom->sin_addr);
    }
}
