// Copyright (c) 2026 The 8BIT developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net_beacon.h"
#include "net.h"
#include "init.h"
#include "addrman.h"
#include "chainparams.h"
#include "util.h"
#include "crypto/hmac_sha256.h"

#include <map>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

static volatile bool fBeaconShutdown = false;
static uint64_t nBeaconNodeID = 0;

static void ComputeBeaconHMAC(const unsigned char* data, size_t len, unsigned char* out)
{
    CHMAC_SHA256 hmac(BEACON_MAGIC, BEACON_MAGIC_LEN);
    hmac.Write(data, len);
    hmac.Finalize(out);
}

static bool BuildBeaconPacket(unsigned char* buf, uint16_t tcpPort, int nHeight)
{
    CService addrLocal;
    CNetAddr addrIPv4("1.2.3.4");
    if (!GetLocal(addrLocal, &addrIPv4))
        return false;

    struct in_addr inAddr;
    if (!addrLocal.GetInAddr(&inAddr))
        return false;

    memset(buf, 0, BEACON_PACKET_SIZE);
    int pos = 0;

    memcpy(buf + pos, BEACON_MAGIC, 4); pos += 4;
    buf[pos++] = BEACON_VERSION;
    buf[pos++] = BEACON_MSG_ANNOUNCE;
    memcpy(buf + pos, &inAddr.s_addr, 4); pos += 4;
    uint16_t port_be = htons(tcpPort);
    memcpy(buf + pos, &port_be, 2); pos += 2;
    uint32_t height = (uint32_t)nHeight;
    memcpy(buf + pos, &height, 4); pos += 4;
    memcpy(buf + pos, &nBeaconNodeID, 8); pos += 8;
    uint32_t ts = (uint32_t)GetTime();
    memcpy(buf + pos, &ts, 4); pos += 4;

    // pos should be 28; HMAC covers bytes 0..27
    unsigned char hmac[32];
    ComputeBeaconHMAC(buf, pos, hmac);
    memcpy(buf + pos, hmac, 32);

    return true;
}

static bool ValidateBeaconPacket(const unsigned char* buf, size_t len)
{
    if (len != BEACON_PACKET_SIZE)
        return false;
    if (memcmp(buf, BEACON_MAGIC, 4) != 0)
        return false;
    if (buf[4] != BEACON_VERSION)
        return false;
    if (buf[5] != BEACON_MSG_ANNOUNCE)
        return false;

    unsigned char hmac[32];
    ComputeBeaconHMAC(buf, 28, hmac);
    if (memcmp(buf + 28, hmac, 32) != 0)
        return false;

    uint32_t ts;
    memcpy(&ts, buf + 24, 4);
    int64_t now = GetTime();
    if (abs(now - (int64_t)ts) > 300)
        return false;

    return true;
}

static CAddress ParseBeaconAddr(const unsigned char* buf)
{
    struct in_addr ip;
    memcpy(&ip.s_addr, buf + 6, 4);
    uint16_t port_be;
    memcpy(&port_be, buf + 10, 2);
    uint16_t port = ntohs(port_be);

    CService svc(ip, port);
    CAddress addr(svc);
    addr.nTime = GetAdjustedTime();
    addr.nServices = NODE_NETWORK;
    return addr;
}

void ThreadUDPBeacon()
{
    RenameThread("8bit-beacon");

    RAND_bytes((unsigned char*)&nBeaconNodeID, sizeof(nBeaconNodeID));

    SOCKET hSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (hSocket == INVALID_SOCKET)
    {
        LogPrintf("Beacon: failed to create UDP socket\n");
        return;
    }

    int optval = 1;
    setsockopt(hSocket, SOL_SOCKET, SO_BROADCAST, (const char*)&optval, sizeof(optval));
    setsockopt(hSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&optval, sizeof(optval));

    struct sockaddr_in bindAddr;
    memset(&bindAddr, 0, sizeof(bindAddr));
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_addr.s_addr = INADDR_ANY;
    bindAddr.sin_port = htons(BEACON_PORT);

    if (bind(hSocket, (struct sockaddr*)&bindAddr, sizeof(bindAddr)) < 0)
    {
        LogPrintf("Beacon: failed to bind UDP port %d\n", BEACON_PORT);
#ifdef WIN32
        closesocket(hSocket);
#else
        close(hSocket);
#endif
        return;
    }

#ifndef WIN32
    int flags = fcntl(hSocket, F_GETFL, 0);
    fcntl(hSocket, F_SETFL, flags | O_NONBLOCK);
#else
    u_long mode = 1;
    ioctlsocket(hSocket, FIONBIO, &mode);
#endif

    LogPrintf("Beacon: UDP listener started on port %d\n", BEACON_PORT);

    std::map<std::string, int64_t> mapRateLimit;
    int64_t nLastLANBroadcast = 0;
    int64_t nLastWANBroadcast = 0;

    while (!fBeaconShutdown && !ShutdownRequested())
    {
        boost::this_thread::interruption_point();

        // --- Receive incoming beacons ---
        unsigned char recvBuf[128];
        struct sockaddr_in senderAddr;
        socklen_t senderLen = sizeof(senderAddr);

        for (int i = 0; i < 20; i++)
        {
            ssize_t n = recvfrom(hSocket, (char*)recvBuf, sizeof(recvBuf), 0,
                                 (struct sockaddr*)&senderAddr, &senderLen);
            if (n <= 0)
                break;

            if (!ValidateBeaconPacket(recvBuf, n))
                continue;

            CAddress addr = ParseBeaconAddr(recvBuf);
            if (!addr.IsValid() || !addr.IsRoutable() || IsLocal(addr))
                continue;

            std::string sIP = addr.ToStringIP();
            int64_t now = GetTime();
            if (mapRateLimit.count(sIP) && (now - mapRateLimit[sIP]) < BEACON_RATE_LIMIT_SECS)
                continue;
            mapRateLimit[sIP] = now;

            if (addrman.Add(addr, CNetAddr(senderAddr.sin_addr)))
                LogPrintf("Beacon: discovered peer %s\n", addr.ToString());
        }

        // Prune rate limit map periodically
        if (mapRateLimit.size() > 1000)
        {
            int64_t now = GetTime();
            for (auto it = mapRateLimit.begin(); it != mapRateLimit.end(); )
            {
                if (now - it->second > 300)
                    it = mapRateLimit.erase(it);
                else
                    ++it;
            }
        }

        int64_t nNow = GetTime();

        // --- LAN broadcast every 60 seconds ---
        if (nNow - nLastLANBroadcast >= BEACON_LAN_INTERVAL)
        {
            unsigned char pkt[BEACON_PACKET_SIZE];
            if (BuildBeaconPacket(pkt, Params().GetDefaultPort(), nBestHeight))
            {
                struct sockaddr_in bcast;
                memset(&bcast, 0, sizeof(bcast));
                bcast.sin_family = AF_INET;
                bcast.sin_addr.s_addr = INADDR_BROADCAST;
                bcast.sin_port = htons(BEACON_PORT);
                sendto(hSocket, (const char*)pkt, BEACON_PACKET_SIZE, 0,
                       (struct sockaddr*)&bcast, sizeof(bcast));
            }
            nLastLANBroadcast = nNow;
        }

        // --- WAN beacon to known peers every 5 minutes ---
        if (nNow - nLastWANBroadcast >= BEACON_WAN_INTERVAL)
        {
            unsigned char pkt[BEACON_PACKET_SIZE];
            if (BuildBeaconPacket(pkt, Params().GetDefaultPort(), nBestHeight))
            {
                vector<CAddress> vAddr = addrman.GetAddr();
                int nSent = 0;
                BOOST_FOREACH(const CAddress& addr, vAddr)
                {
                    if (!addr.IsRoutable() || IsLocal(addr))
                        continue;

                    struct in_addr inAddr;
                    if (!addr.GetInAddr(&inAddr))
                        continue;

                    struct sockaddr_in dest;
                    memset(&dest, 0, sizeof(dest));
                    dest.sin_family = AF_INET;
                    dest.sin_addr = inAddr;
                    dest.sin_port = htons(BEACON_PORT);
                    sendto(hSocket, (const char*)pkt, BEACON_PACKET_SIZE, 0,
                           (struct sockaddr*)&dest, sizeof(dest));
                    nSent++;

                    if (nSent >= 250)
                        break;
                }
                if (nSent > 0)
                    LogPrintf("Beacon: sent announcement to %d known peers\n", nSent);
            }
            nLastWANBroadcast = nNow;
        }

        MilliSleep(1000);
    }

#ifdef WIN32
    closesocket(hSocket);
#else
    close(hSocket);
#endif
    LogPrintf("Beacon: UDP thread exiting\n");
}

void StartBeacon(boost::thread_group& threadGroup)
{
    fBeaconShutdown = false;
    threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "beacon", &ThreadUDPBeacon));
}

void StopBeacon()
{
    fBeaconShutdown = true;
}
