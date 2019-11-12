use nb2::packets::icmp::v6::{EchoReply, EchoRequest, Icmpv6};
use nb2::packets::ip::v6::Ipv6;
use nb2::packets::{Ethernet, Packet};
use nb2::settings::load_config;
use nb2::{Batch, Mbuf, Pipeline, Poll, PortQueue, Result, Runtime};
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn reply_echo(packet: &Mbuf) -> Result<Icmpv6<Ipv6, EchoReply>> {
    let reply = Mbuf::new()?;

    let ethernet = packet.peek::<Ethernet>()?;
    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(ethernet.dst());
    reply.set_dst(ethernet.src());

    let ipv6 = ethernet.peek::<Ipv6>()?;
    let mut reply = reply.push::<Ipv6>()?;
    reply.set_src(ipv6.dst());
    reply.set_dst(ipv6.src());

    let request = ipv6.peek::<Icmpv6<Ipv6, EchoRequest>>()?;
    let mut reply = reply.push::<Icmpv6<Ipv6, EchoReply>>()?;
    reply.set_identifier(request.identifier());
    reply.set_seq_no(request.seq_no());
    reply.set_data(request.data())?;
    reply.cascade();

    debug!(?request);
    debug!(?reply);

    Ok(reply)
}

fn install(q: PortQueue) -> impl Pipeline {
    Poll::new(q.clone()).replace(reply_echo).send(q)
}

fn main() -> Result<()> {
    let subscriber = fmt::Subscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let config = load_config()?;
    debug!(?config);

    Runtime::build(config)?
        .add_pipeline_to_port("eth1", install)?
        .execute()
}
