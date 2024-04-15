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
