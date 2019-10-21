use crate::packets::{Header, Packet};
use crate::{Mbuf, Result};

/// Unit header.
impl Header for () {}

// make the message buffer behave like a packet.
impl Packet for Mbuf {
    type Header = ();
    type Envelope = Mbuf;

    #[doc(hidden)]
    #[inline]
    fn mbuf(&self) -> &Mbuf {
        self
    }

    #[doc(hidden)]
    #[inline]
    fn mbuf_mut(&mut self) -> &mut Mbuf {
        self
    }

    #[inline]
    fn envelope(&self) -> &Self::Envelope {
        self
    }

    #[inline]
    fn envelope_mut(&mut self) -> &mut Self::Envelope {
        self
    }

    #[doc(hidden)]
    #[inline]
    fn header(&self) -> &Self::Header {
        unreachable!("raw packet has no defined header!");
    }

    #[doc(hidden)]
    #[inline]
    fn header_mut(&mut self) -> &mut Self::Header {
        unreachable!("raw packet has no defined header!");
    }

    #[inline]
    fn offset(&self) -> usize {
        0
    }

    #[inline]
    fn header_len(&self) -> usize {
        0
    }

    #[doc(hidden)]
    #[inline]
    fn do_parse(envelope: Self::Envelope) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(envelope)
    }

    #[doc(hidden)]
    #[inline]
    fn do_push(envelope: Self::Envelope) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(envelope)
    }

    #[inline]
    fn remove(self) -> Result<Self::Envelope> {
        Ok(self)
    }

    #[inline]
    fn cascade(&mut self) {
        // noop
    }

    #[inline]
    fn deparse(self) -> Self::Envelope {
        self
    }

    #[inline]
    fn reset(self) -> Mbuf {
        self
    }
}
