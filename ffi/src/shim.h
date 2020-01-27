/*
* Copyright 2019 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <rte_mbuf.h>
#include <rte_mempool.h>

/**
 * Error number value, stored per-thread, which can be queried after
 * calls to certain functions to determine why those functions failed.
 */
int _rte_errno(void);

/**
 * Get the ID of the physical socket of the specified lcore.
 */
unsigned _rte_lcore_to_socket_id(unsigned lcore_id);

/**
 * Allocate a new mbuf from a mempool.
 */
struct rte_mbuf *_rte_pktmbuf_alloc(struct rte_mempool *mp);

/**
 * Free a packet mbuf back into its original mempool.
 */
void _rte_pktmbuf_free(struct rte_mbuf *m);

/**
 * Allocate a bulk of mbufs, initialize refcnt and reset the fields to
 * default values.
 */
int _rte_pktmbuf_alloc_bulk(
    struct rte_mempool *pool,
    struct rte_mbuf **mbufs,
    unsigned count);

/**
 * Put several objects back in the mempool.
 */
void _rte_mempool_put_bulk(
    struct rte_mempool *mp,
    void *const *obj_table,
    unsigned int n);

/**
 * Retrieve a burst of input packets from a receive queue of an Ethernet
 * device. The retrieved packets are stored in *rte_mbuf* structures whose
 * pointers are supplied in the *rx_pkts* array.
 */
uint16_t _rte_eth_rx_burst(
    uint16_t port_id,
    uint16_t queue_id,
    struct rte_mbuf **rx_pkts,
    const uint16_t nb_pkts);

/**
 * Send a burst of output packets on a transmit queue of an Ethernet device.
 */
uint16_t _rte_eth_tx_burst(
    uint16_t port_id,
    uint16_t queue_id,
    struct rte_mbuf **tx_pkts,
    uint16_t nb_pkts);
