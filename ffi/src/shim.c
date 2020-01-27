#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

int _rte_errno(void) {
    return rte_errno;
}

struct rte_mbuf *_rte_pktmbuf_alloc(struct rte_mempool *mp) {
    return rte_pktmbuf_alloc(mp);
}

void _rte_pktmbuf_free(struct rte_mbuf *m) {
    rte_pktmbuf_free(m);
}

int _rte_pktmbuf_alloc_bulk(
    struct rte_mempool *pool,
    struct rte_mbuf **mbufs,
    unsigned count) {
    return rte_pktmbuf_alloc_bulk(pool, mbufs, count);
}

void _rte_mempool_put_bulk(
    struct rte_mempool *mp,
    void *const *obj_table,
    unsigned int n) {
    rte_mempool_put_bulk(mp, obj_table, n);
}

uint16_t _rte_eth_rx_burst(
    uint16_t port_id,
    uint16_t queue_id,
    struct rte_mbuf **rx_pkts,
    const uint16_t nb_pkts) {
    return rte_eth_rx_burst(port_id, queue_id, rx_pkts, nb_pkts);
}

uint16_t _rte_eth_tx_burst(
    uint16_t port_id,
    uint16_t queue_id,
    struct rte_mbuf **tx_pkts,
    uint16_t nb_pkts) {
    return rte_eth_tx_burst(port_id, queue_id, tx_pkts, nb_pkts);
}
