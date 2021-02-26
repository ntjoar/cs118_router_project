/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

/* IMPLEMENTED BEGIN */
/* 
 * Validate ICMP checksum 
 */
void validICMPChecksum(Buffer packet, icmp_hdr* icmp_header_packet) {
  uint16_t checksum = icmp_header_packet->icmp_sum;
  icmp_header_packet->icmp_sum = 0;

  int remainder = packet.size() - (sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr));

  if(checksum != cksum(icmp_header_packet, sizeof(icmp_hdr) + remainder)) {
    std::cerr << "Error: Bad ICMP Checksum. Packet dropped";
    return;
  }
}

/*
 * Decrement TTL and print out if TTL dead
 */
void decrementTTL(ip_hdr* ip_header) {
  /* Decrement TTL, recompute checksum */
  ip_header->ip_ttl -= 1;
  /* See utils.cpp */
  ip_header->ip_sum = cksum(ip_header, sizeof(ip_hdr));

  /* IP Packet TTL expired */
  if(ip_header->ip_sum == 0) {
    std::cerr << "ERR: IP packet TTL has expired" << std::endl;
    return;
  }
}

/*
 * Swap ethernet headers
 */
void prepareEthernet(Buffer& echo_reply_packet) {
  /* Change MAC Addr */
  ethernet_hdr* echo_reply = (ethernet_hdr*)echo_reply_packet.data();
  uint8_t tmp_src[ETHER_ADDR_LEN];

  /* Simple swapping */
  memcpy(tmp_src, echo_reply->ether_shost, ETHER_ADDR_LEN);
  memcpy(echo_reply->ether_shost, echo_reply->ether_dhost, ETHER_ADDR_LEN);
  memcpy(echo_reply->ether_dhost, tmp_src, ETHER_ADDR_LEN);
}

/*
 * ICMP preparation
 */
void prepareICMP(Buffer& echo_reply_packet) {

  /* Swap echo reply type */
  icmp_hdr* echo_reply = (icmp_hdr*)(echo_reply_packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
  echo_reply -> icmp_sum = 0;
  echo_reply -> icmp_type = 0;

  int totalremaining_after_icmp_echo_reply = echo_reply_packet.size() - (sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr));
  echo_reply -> icmp_sum = cksum(echo_reply, sizeof(icmp_hdr) + totalremaining_after_icmp_echo_reply);
}

/*
 * IP preparation
 */
void prepareIP(Buffer& echo_reply_packet) {
  /*
   * Swap src/dest IP
   * TTL = 64
   * Recompute IP checksum
   */
  ip_hdr* echo_reply_ip_header = (ip_hdr*)(echo_reply_packet.data() + sizeof(ethernet_hdr));
  echo_reply_ip_header->ip_ttl = 64;

  uint32_t temp_src = echo_reply_ip_header->ip_src;
  echo_reply_ip_header->ip_src = echo_reply_ip_header->ip_dst;
  echo_reply_ip_header->ip_dst = temp_src;

  echo_reply_ip_header->ip_sum = 0;
  echo_reply_ip_header->ip_sum = cksum(echo_reply_ip_header, sizeof(ip_hdr));
}

/*
 * More like an overall wrapper we just call once and it calls all of the above
 */
void prepareEcho(Buffer& echo_reply_packet) {
  prepareEthernet(echo_reply_packet);
  prepareICMP(echo_reply_packet);
  prepareIP(echo_reply_packet);
}

/* 
 * Handle an incoming packet 
 */
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  /* Provided BEGIN */
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;
  /* Provided END */

  /* Check broadcast address */
  std::string broadcast_addr = "ff:ff:ff:ff:ff:ff";
  if(!((macToString(packet) == macToString(iface->addr)) ||
       (macToString(packet) == broadcast_addr))) {
    std::cerr << "Packet is not this router's responsiblity...";
    return;
  }

  if(ethertype((const uint8_t*)packet.data()) == ethertype_ip) {
    /* Variables for this */
    Buffer orig_packet_copy(packet);
    ip_hdr* header = (ip_hdr*)(orig_packet_copy.data() + sizeof(ethernet_hdr));

    /* Sanity check: minimum packet size */
    size_t min_packet_size = sizeof(ethernet_hdr) + sizeof(ip_hdr);
    if((packet.size() < min_packet_size) || (header->ip_len < sizeof(ip_hdr))){
      std::cerr << "Error: IP packet does not meet minimum size requirements." << std::endl;
      return;
    }

    /* Validate IP Checksum */
    /* See utils.cpp */
    uint16_t checksum = header->ip_sum;
    header->ip_sum = 0;
    if(checksum != cksum(header, sizeof(ip_hdr))) {
      std::cerr << "Error: Bad checksum. IP packet header is corrupted." << std::endl;
      return;
    }

    /* See simple_router.hpp */
    /* See protocol.hpp */
    for(auto this_iface: m_ifaces) {
      if((header->ip_dst == this_iface.ip) && (header->ip_p == ip_protocol_icmp)) {
        icmp_hdr* icmp_header_packet = (icmp_hdr*)(packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
        int icmp_type = (int)(icmp_header_packet->icmp_type);

        if(icmp_type == 8) {
          validICMPChecksum(packet, icmp_header_packet);
          Buffer echo_reply(packet);
          prepareEcho(echo_reply);
          sendPacket(echo_reply, iface->name);
          return;
        }
      } else if(header->ip_dst == this_iface.ip){ // Ignore other packets destined for us
        return;
      }
    }

    decrementTTL(header);
    RoutingTableEntry route_ent = m_routingTable.lookup(header->ip_dst);

    const Interface* for_iface = findIfaceByName(route_ent.ifName);
    std::shared_ptr<ArpEntry> arp_entry = m_arp.lookup(header->ip_dst);

    /* Get address to send it to */
    if(arp_entry == nullptr) {
      m_arp.queueRequest(header->ip_dst, orig_packet_copy, for_iface->name);
      /* Create eth and arp */
      Buffer req_buf(sizeof(arp_hdr) + sizeof(ethernet_hdr));
      uint8_t* req_ptr = (uint8_t*)req_buf.data();

      ethernet_hdr* req_eth_header = (ethernet_hdr*)req_ptr;
      req_eth_header->ether_type = htons(ethertype_arp);
      memcpy(req_eth_header->ether_shost, for_iface-> addr.data(), ETHER_ADDR_LEN); // Src
      memcpy(req_eth_header->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN); // Dest

      arp_hdr* req_arp_header = (arp_hdr*)(req_ptr + sizeof(ethernet_hdr));
      req_arp_header->arp_hln = ETHER_ADDR_LEN;
      req_arp_header->arp_pro = htons(ethertype_ip);
      req_arp_header->arp_op = htons(arp_op_request);
      req_arp_header->arp_hrd = htons(arp_hrd_ethernet);
      req_arp_header->arp_pln = 4;
      
      memcpy(req_arp_header->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
      memcpy(req_arp_header->arp_sha, for_iface->addr.data(), ETHER_ADDR_LEN);
      req_arp_header->arp_sip = for_iface->ip;
      req_arp_header->arp_tip = header->ip_dst;

      sendPacket(req_buf, for_iface->name);
    } else {
      ethernet_hdr* temp = (ethernet_hdr*)(orig_packet_copy.data());
      temp->ether_type = htons(ethertype_ip);
      memcpy(temp->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
      memcpy(temp->ether_shost, for_iface->addr.data(), ETHER_ADDR_LEN);

      sendPacket(orig_packet_copy, for_iface->name);
    }
    return;
  } else if(ethertype((const uint8_t*)packet.data()) == ethertype_arp) {
    /* Get arp data and set pointer */
    arp_hdr* arp_header = (arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
    unsigned short arp_oper = ntohs(arp_header->arp_op);

    /* What type of operation are we handling */
    if(arp_oper == arp_op_request) {
      std::cerr << "Handling ARP Request" << std::endl;
      if(arp_header->arp_tip == iface->ip) {
        /* Create buffer */
        uint8_t req_sz = sizeof(ethernet_hdr) + sizeof(arp_hdr);
        Buffer req_buf(req_sz);
        uint8_t* req_packet = (uint8_t *)req_buf.data();

        ethernet_hdr* eth_head = (ethernet_hdr *)req_packet;
        arp_hdr* arp_head = (arp_hdr *)(req_packet + sizeof(ethernet_hdr));

        /* Create our ethernet header */
        memcpy(eth_head->ether_dhost, &(arp_header->arp_sha), ETHER_ADDR_LEN);
        memcpy(eth_head->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        eth_head->ether_type = htons(ethertype_arp);

        /* Create our ARP header */
        arp_head->arp_hln = ETHER_ADDR_LEN;
        arp_head->arp_pro = htons(ethertype_ip);
        arp_head->arp_op = htons(arp_op_reply);
        arp_head->arp_hrd = htons(arp_hrd_ethernet);
        arp_head->arp_pln = 4;

        memcpy(arp_head->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(arp_head->arp_tha, &(arp_header->arp_sha), ETHER_ADDR_LEN);
        arp_head->arp_sip = iface->ip;
        arp_head->arp_tip = arp_header->arp_sip;

        sendPacket(req_buf, iface->name);

        return;
      }

      std::cerr << "Error: target IP does not match. Packet dropped" << std::endl;
      return;
    } else if(arp_oper == arp_op_reply) {
      std::cerr << "Handling ARP Reply" << std::endl;

      /* Get source hardware */
      Buffer arp_rep_mac(ETHER_ADDR_LEN);
      memcpy(arp_rep_mac.data(), arp_header->arp_sha, ETHER_ADDR_LEN);

      /* Add IP to MAC mapping in cache */
      std::shared_ptr<ArpRequest> arp_rep_map = m_arp.insertArpEntry(arp_rep_mac, arp_header->arp_sip);

      if(arp_rep_map != nullptr) { // ensure we have good data
        std::list<PendingPacket>::const_iterator iter = arp_rep_map->packets.begin();
        sendPacket(iter->packet,iter->iface);
        m_arp.removeRequest(arp_rep_map);
      }

      return;
    }
  } 

  return;
}

/* IMPLEMENTED END */

SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}


} // namespace simple_router {
