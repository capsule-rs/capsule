/// known issues:
// 1. https://github.com/rust-lang/rust/issues/54341

// all the necessary DPDK functions, types and constants are defined
// in the following header files.
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_kni.h>

// libnuma functions and types
#include <numa.h>

// bindgen can't generate bindings for static functions defined in C
// header files. these shims are necessary to expose them to FFI.

/**
 * Error number value, stored per-thread, which can be queried after
 * calls to certain functions to determine why those functions failed.
 */
int _rte_errno(void);

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
