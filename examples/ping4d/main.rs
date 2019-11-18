use nb2::batch::Either;
use nb2::packets::icmp::v4::{EchoReply, EchoRequest, Icmpv4};
use nb2::packets::ip::v4::Ipv4;
use nb2::packets::ip::ProtocolNumbers;
use nb2::packets::{EtherTypes, Ethernet, Packet};
use nb2::settings::load_config;
use nb2::{Batch, Mbuf, Pipeline, Poll, PortQueue, Result, Runtime};
use tracing::{debug, Level};
use tracing_subscriber::fmt;

fn reply_echo(packet: &Ipv4) -> Result<Icmpv4<Ipv4, EchoReply>> {
    let reply = Mbuf::new()?;

    let mut reply = reply.push::<Ethernet>()?;
    reply.set_src(packet.envelope().dst());
    reply.set_dst(packet.envelope().src());

    let mut reply = reply.push::<Ipv4>()?;
    reply.set_src(packet.dst());
    reply.set_dst(packet.src());
    reply.set_ttl(255);

    let request = packet.peek::<Icmpv4<Ipv4, EchoRequest>>()?;
    let mut reply = reply.push::<Icmpv4<Ipv4, EchoReply>>()?;
    reply.set_identifier(request.identifier());
    reply.set_seq_no(request.seq_no());
    reply.set_data(request.data())?;
    reply.cascade();

    debug!(?request);
    debug!(?reply);

    Ok(reply)
}

fn filter_for_icmpv4(packet: Mbuf) -> Result<Either<Ipv4>> {
    let ethernet = packet.parse::<Ethernet>()?;
    if ethernet.ether_type() != EtherTypes::Ipv4 {
        Ok(Either::Drop(ethernet.reset()))
    } else {
        let ipv4 = ethernet.parse::<Ipv4>()?;
        if ipv4.protocol() == ProtocolNumbers::Icmpv4 {
            Ok(Either::Keep(ipv4))
        } else {
            Ok(Either::Drop(ipv4.reset()))
        }
    }
}

fn install(q: PortQueue) -> impl Pipeline {
    Poll::new(q.clone())
        .filter_map(filter_for_icmpv4)
        .replace(reply_echo)
        .send(q)
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
