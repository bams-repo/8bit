// Copyright (c) 2026 The 8BIT developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NET_BEACON_H
#define BITCOIN_NET_BEACON_H

#include <boost/thread.hpp>

static const int BEACON_PORT = 18887;
static const int BEACON_MAGIC_LEN = 4;
static const unsigned char BEACON_MAGIC[4] = {0x38, 0x42, 0x49, 0x54}; // "8BIT"
static const unsigned char BEACON_VERSION = 1;
static const unsigned char BEACON_MSG_ANNOUNCE = 0x01;
static const int BEACON_PACKET_SIZE = 60;
static const int BEACON_LAN_INTERVAL = 60;
static const int BEACON_WAN_INTERVAL = 300;
static const int BEACON_RATE_LIMIT_SECS = 30;

void ThreadUDPBeacon();
void StartBeacon(boost::thread_group& threadGroup);
void StopBeacon();

#endif // BITCOIN_NET_BEACON_H
