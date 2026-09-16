//! The sync protocol's request-response codec: CBOR, with size limits we set.
//!
//! This exists because `libp2p::request_response::cbor::Behaviour` hard-codes its limits as
//! private constants — 1 MiB for a request, 10 MiB for a response in libp2p 0.54 — with no way to
//! configure them, and it enforces the response limit by *truncation*:
//!
//! ```ignore
//! io.take(RESPONSE_SIZE_MAXIMUM).read_to_end(&mut vec).await?;
//! cbor4ii::serde::from_slice(vec.as_slice())    // on a buffer cut mid-message
//! ```
//!
//! A response over the limit is therefore not rejected with a clear error; it is silently cut and
//! then fails to decode, which is what chain 8 reported as
//! `IO error on outbound stream: Eof { name: "bytes", expect: .. }` for every peer asked for the
//! batch containing the chain's first 1.3 MB transfer proof. A node that fell behind such a block
//! could not rejoin at all: the same range was requested, truncated and retried forever.
//!
//! So the limits are ours, derived from what a batch is actually allowed to be
//! ([`super::SYNC_MAX_WIRE_BYTES`]), and the *writer* checks the encoded size before it writes —
//! a message too large fails on the server, where it can be logged against the peer that built
//! it, rather than as a decode error on a reader that cannot tell truncation from corruption.
//!
//! The serializer is `cbor4ii::serde`, exactly what libp2p's codec uses, so
//! [`cbor_size`] measures what the wire will carry.

use futures::prelude::*;
use libp2p::request_response;
use libp2p::StreamProtocol;
use serde::{de::DeserializeOwned, Serialize};
use std::io;
use std::marker::PhantomData;

/// Serialized size of a value under the codec's own serializer.
///
/// Used by the server to add up a sync batch as it fills it, so the budget is measured in the
/// units the wire charges in, not in bincode's.
pub fn cbor_size<T: Serialize>(value: &T) -> io::Result<usize> {
    cbor4ii::serde::to_vec(Vec::new(), value)
        .map(|v| v.len())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
}

/// A CBOR codec whose request and response size limits are given rather than assumed.
pub struct Codec<Req, Resp> {
    request_size_maximum: u64,
    response_size_maximum: u64,
    phantom: PhantomData<(Req, Resp)>,
}

impl<Req, Resp> Codec<Req, Resp> {
    pub fn new(request_size_maximum: u64, response_size_maximum: u64) -> Self {
        Codec { request_size_maximum, response_size_maximum, phantom: PhantomData }
    }
}

impl<Req, Resp> Clone for Codec<Req, Resp> {
    fn clone(&self) -> Self {
        Codec::new(self.request_size_maximum, self.response_size_maximum)
    }
}

/// Read one length-unprefixed CBOR message, refusing an oversized one instead of truncating it.
///
/// One byte more than the limit is read on purpose: if it arrives, the message is over the limit
/// and the error says so, where `take(limit)` alone would hand a short buffer to the decoder and
/// surface a `Eof`/`InvalidData` that names nothing useful.
async fn read_limited<T>(io: &mut T, limit: u64, what: &'static str) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut vec = Vec::new();
    io.take(limit.saturating_add(1)).read_to_end(&mut vec).await?;
    if vec.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sync {what} exceeds the {limit}-byte limit; the sender's batch budget is wrong"),
        ));
    }
    Ok(vec)
}

/// Takes `value` by value, not by reference: `&V` would need `V: Sync` for the returned future to
/// be `Send`, which the `Codec` trait requires.
async fn write_limited<T, V>(io: &mut T, value: V, limit: u64, what: &'static str) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    V: Serialize,
{
    let data = cbor4ii::serde::to_vec(Vec::new(), &value)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    if data.len() as u64 > limit {
        // Fail here rather than write a message the peer is guaranteed not to be able to read.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("refusing to send a {}-byte sync {what}, over the {limit}-byte limit", data.len()),
        ));
    }
    io.write_all(&data).await
}

impl<Req, Resp> request_response::Codec for Codec<Req, Resp>
where
    Req: Send + Serialize + DeserializeOwned,
    Resp: Send + Serialize + DeserializeOwned,
{
    type Protocol = StreamProtocol;
    type Request = Req;
    type Response = Resp;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Req>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_limited(io, self.request_size_maximum, "request").await?;
        cbor4ii::serde::from_slice(vec.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Resp>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_limited(io, self.response_size_maximum, "response").await?;
        cbor4ii::serde::from_slice(vec.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Req) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // No `io.close()`: `libp2p_request_response`'s handler closes the stream itself the moment
        // this returns, which is also what gives the reader its EOF.
        write_limited(io, req, self.request_size_maximum, "request").await
    }

    async fn write_response<T>(&mut self, _: &Self::Protocol, io: &mut T, res: Resp) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        // Closed by the handler, as above.
        write_limited(io, res, self.response_size_maximum, "response").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{SyncRequest, SyncResponse, SYNC_REQUEST_WIRE_LIMIT, SYNC_RESPONSE_WIRE_LIMIT};
    use libp2p::request_response::Codec as _;
    use shrugg_core::consensus::CommittedBlock;
    use shrugg_core::types::block::{Block, BlockHeader, QuorumCertificate, Vote};
    use shrugg_core::{Hash, Keypair};

    fn proto() -> StreamProtocol {
        StreamProtocol::new("/shrugg/test/sync/1")
    }

    /// A committed block shaped like chain 8's: `votes` votes in the header's `justify` QC and in
    /// the QC that certifies it, each vote a 1312-byte Dilithium2 key and a 2420-byte signature.
    fn chain_8_block(height: u64, ks: &[Keypair], votes: usize) -> CommittedBlock {
        let parent = Hash::digest(&height.to_be_bytes());
        let qc = |view: u64, hash: Hash| QuorumCertificate {
            view,
            block_hash: hash,
            votes: ks[..votes].iter().map(|k| Vote::sign(view, hash, k)).collect(),
        };
        let header = BlockHeader {
            height,
            view: height,
            parent,
            proposer: ks[0].public_key().clone(),
            timestamp_ms: height,
            tx_root: Hash::ZERO,
            state_root: parent,
            justify: qc(height.saturating_sub(1), parent),
        };
        let block = Block::sign(header, vec![], &ks[0]);
        let hash = block.hash();
        CommittedBlock { block, pruned: Vec::new(), qc: qc(height, hash), receipts: Vec::new(), deposits: Vec::new() }
    }

    fn chain_8_batch(n: u64) -> SyncResponse {
        let ks: Vec<Keypair> = (1..=18u8).map(|i| Keypair::from_seed([i; 32]).unwrap()).collect();
        SyncResponse::Blocks((1..=n).map(|h| chain_8_block(h, &ks, 18)).collect())
    }

    /// Write a response with one codec and read it back with another, as two peers would.
    async fn round_trip(
        response: SyncResponse,
        write_limit: u64,
        read_limit: u64,
    ) -> (io::Result<()>, io::Result<SyncResponse>) {
        let mut writer: Codec<SyncRequest, SyncResponse> = Codec::new(SYNC_REQUEST_WIRE_LIMIT, write_limit);
        let mut buf: Vec<u8> = Vec::new();
        let wrote = writer.write_response(&proto(), &mut buf, response).await;
        let mut reader: Codec<SyncRequest, SyncResponse> = Codec::new(SYNC_REQUEST_WIRE_LIMIT, read_limit);
        let mut cursor = futures::io::Cursor::new(buf);
        let read = reader.read_response(&proto(), &mut cursor).await;
        (wrote, read)
    }

    /// The chain-8 failure, reproduced at the layer it happened on: a 100-block batch of *empty*
    /// 18-validator blocks is over 13 MiB, and a reader with libp2p's hard-coded 10 MiB limit
    /// truncates it and then fails to decode — the `Eof { name: "bytes", .. }` four peers returned.
    #[tokio::test]
    async fn libp2ps_ten_mebibyte_reader_truncates_a_chain_8_batch_and_cannot_decode_it() {
        const LIBP2P_DEFAULT_RESPONSE_MAXIMUM: u64 = 10 << 20;
        let batch = chain_8_batch(100);
        let size = cbor_size(&batch).unwrap() as u64;
        assert!(size > LIBP2P_DEFAULT_RESPONSE_MAXIMUM, "expected over 10 MiB, measured {size} B");

        // Written by a server with a budget that does not know better, read by libp2p's limit.
        let (wrote, read) = round_trip(batch, u64::MAX, LIBP2P_DEFAULT_RESPONSE_MAXIMUM).await;
        assert!(wrote.is_ok(), "the server writes it happily: {wrote:?}");
        let err = read.expect_err("a truncated batch must not decode");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    /// The same batch, over the limits this node sets: it round-trips, and comes back whole.
    #[tokio::test]
    async fn a_batch_within_our_limit_round_trips_intact() {
        let batch = chain_8_batch(40);
        let size = cbor_size(&batch).unwrap() as u64;
        assert!(size <= SYNC_RESPONSE_WIRE_LIMIT, "{size} B should be inside our limit");
        let (wrote, read) = round_trip(batch.clone(), SYNC_RESPONSE_WIRE_LIMIT, SYNC_RESPONSE_WIRE_LIMIT).await;
        wrote.expect("written");
        let back = read.expect("read back");
        match (back, batch) {
            (SyncResponse::Blocks(a), SyncResponse::Blocks(b)) => {
                assert_eq!(a.len(), b.len());
                assert_eq!(a, b, "the batch must come back byte-identical");
            }
            _ => panic!("wrong response variant"),
        }
    }

    /// A response past the limit fails on the *writer*, naming the limit, rather than going out to
    /// be truncated by a reader that can only report a decode error.
    #[tokio::test]
    async fn a_response_over_the_limit_is_refused_by_the_writer() {
        let batch = chain_8_batch(100);
        let mut codec: Codec<SyncRequest, SyncResponse> = Codec::new(SYNC_REQUEST_WIRE_LIMIT, SYNC_RESPONSE_WIRE_LIMIT);
        let mut buf: Vec<u8> = Vec::new();
        let err = codec.write_response(&proto(), &mut buf, batch).await.expect_err("must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains(&SYNC_RESPONSE_WIRE_LIMIT.to_string()), "{err}");
        assert!(buf.is_empty(), "nothing should have been written");
    }

    /// A reader that is handed more than its limit says so, instead of decoding a short buffer.
    #[tokio::test]
    async fn a_reader_rejects_an_oversized_message_by_name() {
        let batch = chain_8_batch(8);
        let size = cbor_size(&batch).unwrap() as u64;
        let (wrote, read) = round_trip(batch, u64::MAX, size - 1).await;
        wrote.expect("written");
        let err = read.expect_err("over the reader's limit");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[tokio::test]
    async fn a_request_round_trips() {
        let mut codec: Codec<SyncRequest, SyncResponse> = Codec::new(SYNC_REQUEST_WIRE_LIMIT, SYNC_RESPONSE_WIRE_LIMIT);
        let mut buf: Vec<u8> = Vec::new();
        codec
            .write_request(&proto(), &mut buf, SyncRequest::Blocks { from_height: 7, max: 100 })
            .await
            .expect("written");
        let mut cursor = futures::io::Cursor::new(buf);
        let back = codec.read_request(&proto(), &mut cursor).await.expect("read back");
        match back {
            SyncRequest::Blocks { from_height, max } => {
                assert_eq!((from_height, max), (7, 100));
            }
            other => panic!("wrong request: {other:?}"),
        }
    }
}
