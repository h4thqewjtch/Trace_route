#include <gtest/gtest.h>

#include "../src/exception.h"
#include "../src/traceroute.h"

TEST(SetDestinationAddress, ExpectedAndActualAddressesAreEqual)
{
    // Arrange
    SOCKADDR_IN actualDestinationAddress;

    // Act
    set_destination_address(actualDestinationAddress,
                            "192.168.0.1");

    // Assert
    EXPECT_EQ(AF_INET, actualDestinationAddress.sin_family);
    ASSERT_EQ(inet_addr("192.168.0.1"), actualDestinationAddress.sin_addr.s_addr);
}

TEST(SetDestinationAddress, ExpectedAndActualAddressesAreDifferent)
{
    // Arrange
    SOCKADDR_IN actualDestinationAddress;

    // Act
    set_destination_address(actualDestinationAddress,
                            "192.168.0.1");

    // Assert
    EXPECT_EQ(AF_INET, actualDestinationAddress.sin_family);
    ASSERT_NE(inet_addr("192.168.0.2"), actualDestinationAddress.sin_addr.s_addr);
}

TEST(SetTimeToLive, ThereIsLocalException)
{
    // Arrange
    SOCKET socket = INVALID_SOCKET;

    // Act

    // Assert
    ASSERT_THROW(
        set_time_to_live(socket, 10),
        LocalException);
}

TEST(CalculateCheckSum, ExpectedAndActualCheckSumsAreEqual)
{
    // Arrange
    USHORT packet[]{
        0x5C88,
        0xDEAE,
        0x8883,
        0x2AE0,
        0x4FB5,
        0x12FC,
        0x550D,
        0x19E2};
    ULONG expectedCheckSum = 0;
    USHORT expectedCheckSumResult, actualCheckSumResult = 0;

    // Act
    for (size_t i = 0; i < sizeof(packet) / sizeof(USHORT); ++i)
    {
        expectedCheckSum += packet[i];
    }
    expectedCheckSum = (expectedCheckSum >> 16) + (expectedCheckSum & 0xffff);
    expectedCheckSum += (expectedCheckSum >> 16);
    expectedCheckSumResult = static_cast<USHORT>(~expectedCheckSum);

    actualCheckSumResult = calculate_check_sum(packet, sizeof(packet));

    // Assert
    ASSERT_EQ(actualCheckSumResult, expectedCheckSumResult);
}

TEST(SetRequestPacket, RequestPacketIsRight)
{
    // Arrange
    char expectedRequestPacket[1024]{}, actualRequestPacket[1024]{};
    int sequenceNumber = 10;

    // Act
    ICMPHeader *icmpHeader = (ICMPHeader *)expectedRequestPacket;
    icmpHeader->messageType = 8;
    icmpHeader->messageCode = 0;
    icmpHeader->identificator = (USHORT)GetCurrentProcessId();
    icmpHeader->messageCheckSum = 0;
    icmpHeader->sequenceNumber = sequenceNumber;
    icmpHeader->messageCheckSum = calculate_check_sum((USHORT *)expectedRequestPacket,
                                                      sizeof(expectedRequestPacket));

    set_request_packet(actualRequestPacket, sizeof(actualRequestPacket), sequenceNumber);

    // Assert
    ASSERT_STREQ(actualRequestPacket, expectedRequestPacket);
}

TEST(ParseResponsePacket, IcmpMessageTypeIsEchoReply)
{
    // Arrange
    char packet[1024]{};
    SOCKADDR_IN destinationAddress;
    char sourceIpAddress[] = "192.168.1.100";
    unsigned short sourcePort = 12345;
    char packetData[] = "";

    // Act
    packet[0] = 0; // ECHO REPLY
    packet[1] = 0; // Net Unreachable
    packet[4] = 0x12;
    packet[5] = 0x34;
    packet[6] = 0x56;
    packet[7] = 0x78;

    memcpy(packet + 8, sourceIpAddress, strlen(sourceIpAddress));
    memcpy(packet + 24, &sourcePort, sizeof(sourcePort));
    memcpy(packet + 28, packetData, strlen(packetData));

    destinationAddress.sin_addr.s_addr = inet_addr("192.168.1.1");

    int returnValue = parse_response_packet(packet, sizeof(packet), &destinationAddress, 10);

    // Assert
    ASSERT_EQ(returnValue, 1);
}

TEST(SendRequestPacket, ThereIsLocalException)
{
    // Arrange
    SOCKET socket = INVALID_SOCKET;
    char requestPacket[1024]{};
    SOCKADDR_IN destinationAddress{};

    // Act

    // Assert
    ASSERT_THROW(
        send_request_packet(socket,
                            requestPacket,
                            sizeof(requestPacket),
                            destinationAddress),
        LocalException);
}

TEST(ReceiveResponsePacket, ThereIsLocalException)
{
    // Arrange
    SOCKET socket = INVALID_SOCKET;
    char responsePacket[1024]{};
    SOCKADDR_IN sourceAddress{};

    // Act

    // Assert
    ASSERT_THROW(
        receive_response_packet(socket,
                                responsePacket,
                                1024,
                                sourceAddress),
        LocalException);
}

int main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
