/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
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

#include "routing-table.hpp"
#include "core/utils.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include <iostream>

namespace simple_router {

/* IMPLEMENTED BEGIN */

/* 
 * Implement a longest prefix matching algorithm 
 */
RoutingTableEntry
RoutingTable::lookup(uint32_t ip) const
{
  /*
   * We want to route using Longest Prefix Matching Algorithm
   * We can do this by going through thhe m_entries list
   * Find matching and replace should one mask be greater than what we have
   * Another route we can take is sorting first then finding entries,
   * Would make code shorter but less efficient
   */
  bool entryFound = false;
  RoutingTableEntry entry_to_return;
  uint32_t mask_to_return;

  for(auto it = m_entries.begin(); it != m_entries.end(); it++) {
    uint32_t masked_ip = it->mask & ip;
    uint32_t masked_entry = it->mask & it->dest;
    if(masked_entry == masked_ip) { // IP is the same
      if((!entryFound)) { // First value found
        entryFound = true;
        mask_to_return = it->mask;
        entry_to_return = *it;
      } else if (it->mask > mask_to_return) { // Entry mask is greater, replace
        entry_to_return = *it;
        mask_to_return = it->mask;
      }
    } // endif(masked_entry == masked_ip)
  } // endfor

  if(!entryFound) {
    throw std::runtime_error("Routing entry not found");
  } else {
    return entry_to_return;
  }
}

/* IMPLEMENTED END */

bool
RoutingTable::load(const std::string& file)
{
  FILE* fp;
  char  line[BUFSIZ];
  char  dest[32];
  char  gw[32];
  char  mask[32];
  char  iface[32];
  struct in_addr dest_addr;
  struct in_addr gw_addr;
  struct in_addr mask_addr;

  if (access(file.c_str(), R_OK) != 0) {
    perror("access");
    return false;
  }

  fp = fopen(file.c_str(), "r");

  while (fgets(line, BUFSIZ, fp) != 0) {
    sscanf(line,"%s %s %s %s", dest, gw, mask, iface);
    if (inet_aton(dest, &dest_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              dest);
      return false;
    }
    if (inet_aton(gw, &gw_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              gw);
      return false;
    }
    if (inet_aton(mask, &mask_addr) == 0) {
      fprintf(stderr,
              "Error loading routing table, cannot convert %s to valid IP\n",
              mask);
      return false;
    }

    addEntry({dest_addr.s_addr, gw_addr.s_addr, mask_addr.s_addr, iface});
  }
  return true;
}

void
RoutingTable::addEntry(RoutingTableEntry entry)
{
  m_entries.push_back(std::move(entry));
}

std::ostream&
operator<<(std::ostream& os, const RoutingTableEntry& entry)
{
  os << ipToString(entry.dest) << "\t\t"
     << ipToString(entry.gw) << "\t"
     << ipToString(entry.mask) << "\t"
     << entry.ifName;
  return os;
}

std::ostream&
operator<<(std::ostream& os, const RoutingTable& table)
{
  os << "Destination\tGateway\t\tMask\tIface\n";
  for (const auto& entry : table.m_entries) {
    os << entry << "\n";
  }
  return os;
}

} // namespace simple_router
