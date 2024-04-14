#include "traceroute.h"

int main(int argc, char **argv)
{
    SOCKET socket = INVALID_SOCKET;
    try
    {
        check_command_line_arguments(argc);
        WSADATA wsaData;
        wsa_startup(wsaData);
        create_socket(socket);
        set_socket_timeout(socket,
                           1000,
                           SO_RCVTIMEO);
        set_socket_timeout(socket,
                           1000,
                           SO_SNDTIMEO);
        SOCKADDR_IN destinationAddress;
        set_destination_address(destinationAddress,
                                argv[1]);
        set_socket_routing(socket);
        std::cout << std::endl
                  << "Tracing route to " << argv[1]
                  << " with a maximum number of hops 50:"
                  << std::endl
                  << std::endl;
        trace_route(socket,
                    destinationAddress);
        std::cout << std::endl
                  << "Tracing route finished" << std::endl
                  << std::endl;
    }
    catch (LocalException localException)
    {
        std::cerr << localException.what() << std::endl;
    }
    catch (const std::exception &exception)
    {
        std::cerr << "Standard exception: " << exception.what() << std::endl
                  << "Tracing route aborted" << std::endl
                  << std::endl;
    }
    catch (...)
    {
        std::cerr << "Something went wrong" << std::endl
                  << "Tracing route aborted" << std::endl
                  << std::endl;
    }
    if (socket != INVALID_SOCKET)
    {
        closesocket(socket);
    }
    WSACleanup();
    return 0;
}

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
    char sendBuffer[1024]{};
    char receiveBuffer[1024]{};
    int dataSize = sizeof(ICMPHeader);
    int quit = 0, seqNumber = 0;
    SOCKADDR_IN sourceAddress;
    int sourceAddressLength = sizeof(sourceAddress);
    for (int timeToLive = 1; timeToLive <= 50 && !quit; timeToLive++)
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
        quit = parse_response(receiveBuffer, receivedBytes, &sourceAddress, timeToLive);
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
        throw LocalException("sendto() failed with error " + std::to_string(WSAGetLastError()));
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
        throw LocalException("recvfrom() failed with error " + std::to_string(WSAGetLastError()));
    }
    return receivedBytes;
}

int parse_response(char *response, int receivedBytes, SOCKADDR_IN *addressFrom, int timeToLive)
{
    IPHeader *ipHeader = (IPHeader *)response;
    USHORT ipHeaderLength = ipHeader->headerLength * 4;
    ICMPHeader *icmpHeader = (ICMPHeader *)(response + ipHeaderLength);
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
        std::cout << responseAddress << std::endl;
        std::cout << "ICMP Message Type: " << icmpHeader->messageType << std::endl
                  << "\t\t" << icmpMessageTypesMap[icmpHeader->messageType] << std::endl
                  << "\tICMP Message Code: " << icmpHeader->messageCode << std::endl
                  << "\t\t" << icmpMessageCodesMap[icmpHeader->messageCode] << std::endl;
    }
    return returnValue;
}