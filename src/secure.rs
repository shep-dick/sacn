//! Experimental authentication and encryption of sACN packets with
//! AES-128-GCM.
//!
//! **This is a proof of concept, not a secure protocol.** It shows how a
//! standard E1.31 packet can be secured in place; it does not address nonce
//! coordination between sources sharing a key, replay protection, or key
//! management.
//!
//! A secured packet is an ordinary E1.31 packet with three changes:
//!
//! 1. The root-layer vector has a flag ORed in: [`AUTH_FLAG`] (authenticated)
//!    or [`ENCRYPT_FLAG`] (authenticated, with the DMX slots encrypted). Legacy
//!    receivers do not recognise the vector and drop the packet.
//! 2. The root-layer length additionally covers the footer.
//! 3. A 28-byte footer is appended: a 12-byte nonce followed by a 16-byte
//!    authentication tag.
//!
//! The whole packet ahead of the footer is authenticated. When encrypting,
//! everything up to and including the START code is associated data and the
//! slots are the ciphertext. Only data packets are encrypted; sync and
//! discovery packets are always sent authenticated-only.
//!
//! [`Sealer::seal`] turns a serialized packet into a secured one in place, and
//! [`open`] reverses it, leaving a standard packet that [`Packet::parse`]
//! accepts.
//!
//! [`Packet::parse`]: crate::packet::Packet::parse

use aes_gcm::aead::{Key, Nonce, Tag};
use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};

use crate::packet::{
    DATA_HEADER_SIZE, ROOT_FLAGS_LENGTH_OFFSET, SECURITY_FOOTER_SIZE, VECTOR_ROOT_E131_DATA,
    VECTOR_ROOT_E131_EXTENDED, flags_and_length, pdu_length,
};

/// Root-vector flag marking an authenticated packet. Placeholder value.
pub const AUTH_FLAG: u32 = 0x0001_0000;

/// Root-vector flag marking an authenticated packet with encrypted slots.
/// Placeholder value.
pub const ENCRYPT_FLAG: u32 = 0x0002_0000;

const FLAG_MASK: u32 = AUTH_FLAG | ENCRYPT_FLAG;

/// Offset of the root-layer vector.
const ROOT_VECTOR_OFFSET: usize = ROOT_FLAGS_LENGTH_OFFSET + 2;
/// Size of the root layer (preamble, flags-and-length, vector, CID).
const ROOT_LAYER_SIZE: usize = ROOT_VECTOR_OFFSET + 4 + 16;
const NONCE_SIZE: usize = 12;

/// A shared AES-128 key.
#[derive(Clone)]
pub struct SecurityKey(Aes128Gcm);

impl SecurityKey {
    /// Creates a key from 16 bytes of key material.
    pub fn new(key: [u8; 16]) -> Self {
        Self(Aes128Gcm::new(&Key::<Aes128Gcm>::from(key)))
    }
}

impl core::fmt::Debug for SecurityKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecurityKey(..)")
    }
}

/// How a [`Sealer`] protects data packets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureMode {
    /// Authenticate the packet; slots stay readable.
    Authenticated,
    /// Authenticate the packet and encrypt its slots. Sync and discovery
    /// packets, which carry no slots, are authenticated only.
    Encrypted,
}

/// Secures outgoing packets: holds the key, the mode and the nonce counter.
#[derive(Clone, Debug)]
pub struct Sealer {
    key: SecurityKey,
    mode: SecureMode,
    counter: u64,
}

impl Sealer {
    /// Creates a sealer whose nonce counter starts at zero.
    pub fn new(key: SecurityKey, mode: SecureMode) -> Self {
        Self {
            key,
            mode,
            counter: 0,
        }
    }

    /// Secures the serialized packet in `buf[..len]` in place, returning the
    /// secured packet's length (`len + 28`).
    ///
    /// # Panics
    ///
    /// Panics if `buf` has no room for the footer, or if `buf[..len]` is not a
    /// serialized sACN packet.
    pub fn seal(&mut self, buf: &mut [u8], len: usize) -> usize {
        let total = len + SECURITY_FOOTER_SIZE;
        let base = read_u32(buf, ROOT_VECTOR_OFFSET);
        assert!(
            base == VECTOR_ROOT_E131_DATA || base == VECTOR_ROOT_E131_EXTENDED,
            "not a serialized sACN packet",
        );
        let encrypt = self.mode == SecureMode::Encrypted && base == VECTOR_ROOT_E131_DATA;
        let flag = if encrypt { ENCRYPT_FLAG } else { AUTH_FLAG };

        // Rewrite the header first: it is part of the associated data.
        write_u32(buf, ROOT_VECTOR_OFFSET, base | flag);
        write_u16(
            buf,
            ROOT_FLAGS_LENGTH_OFFSET,
            flags_and_length(total - ROOT_FLAGS_LENGTH_OFFSET),
        );

        let mut nonce = [0u8; NONCE_SIZE];
        nonce[4..].copy_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;

        let split = if encrypt { DATA_HEADER_SIZE } else { len };
        let (aad, rest) = buf[..total].split_at_mut(split);
        let (msg, footer) = rest.split_at_mut(len - split);
        let tag = self
            .key
            .0
            .encrypt_inout_detached(&Nonce::<Aes128Gcm>::from(nonce), aad, msg.into())
            .expect("an sACN packet is within AES-GCM's length limits");

        footer[..NONCE_SIZE].copy_from_slice(&nonce);
        footer[NONCE_SIZE..].copy_from_slice(&tag);
        total
    }
}

/// Verifies (and, if encrypted, decrypts) the secured packet in `buf[..len]`
/// in place, restoring the standard root vector and length. Returns the length
/// of the resulting standard packet, ready for
/// [`Packet::parse`](crate::packet::Packet::parse).
///
/// Returns `None` if the packet is not a secured packet, is malformed, or fails
/// authentication.
pub fn open(key: &SecurityKey, buf: &mut [u8], len: usize) -> Option<usize> {
    if len > buf.len() || len < ROOT_LAYER_SIZE + SECURITY_FOOTER_SIZE {
        return None;
    }
    let vector = read_u32(buf, ROOT_VECTOR_OFFSET);
    let base = vector & !FLAG_MASK;
    let encrypted = match vector & FLAG_MASK {
        AUTH_FLAG => false,
        ENCRYPT_FLAG => true,
        _ => return None,
    };
    // Only data packets are ever encrypted.
    let known = match base {
        VECTOR_ROOT_E131_DATA => true,
        VECTOR_ROOT_E131_EXTENDED => !encrypted,
        _ => false,
    };
    if !known {
        return None;
    }
    let root_len = pdu_length(read_u16(buf, ROOT_FLAGS_LENGTH_OFFSET));
    if ROOT_FLAGS_LENGTH_OFFSET + root_len != len {
        return None;
    }

    let body = len - SECURITY_FOOTER_SIZE;
    let split = if encrypted { DATA_HEADER_SIZE } else { body };
    if split > body {
        return None;
    }
    let (packet, footer) = buf[..len].split_at_mut(body);
    let nonce = Nonce::<Aes128Gcm>::try_from(&footer[..NONCE_SIZE]).ok()?;
    let tag = Tag::<Aes128Gcm>::try_from(&footer[NONCE_SIZE..]).ok()?;
    let (aad, msg) = packet.split_at_mut(split);
    key.0
        .decrypt_inout_detached(&nonce, aad, msg.into(), &tag)
        .ok()?;

    write_u32(buf, ROOT_VECTOR_OFFSET, base);
    write_u16(
        buf,
        ROOT_FLAGS_LENGTH_OFFSET,
        flags_and_length(body - ROOT_FLAGS_LENGTH_OFFSET),
    );
    Some(body)
}

fn read_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

fn read_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn write_u16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

fn write_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{CodecErrorKind, VectorLayer};
    use crate::packet::{
        DataPacket, MAX_PACKET_SIZE, Packet, Payload, SyncPacket, UniverseDiscoveryPacket,
        UniverseList,
    };
    use crate::types::{Cid, SequenceNumber};

    const KEY: [u8; 16] = [7; 16];
    const CID: Cid = Cid::from_bytes([0x42; 16]);
    const LEVELS: [u8; 8] = [0, 1, 2, 3, 250, 251, 252, 253];
    const UNIVERSES: [u8; 4] = [0, 1, 0, 2];

    fn level_packet() -> Packet<'static> {
        Packet {
            cid: CID,
            payload: Payload::Data(DataPacket {
                source_name: "secure",
                priority: 100,
                sync_address: 0,
                sequence_number: SequenceNumber::new(1),
                preview: false,
                stream_terminated: false,
                force_sync: false,
                universe: 1,
                start_code: 0x00,
                values: &LEVELS,
            }),
        }
    }

    fn sync_packet() -> Packet<'static> {
        Packet {
            cid: CID,
            payload: Payload::Sync(SyncPacket {
                sequence_number: SequenceNumber::new(3),
                sync_address: 9,
            }),
        }
    }

    fn discovery_packet() -> Packet<'static> {
        Packet {
            cid: CID,
            payload: Payload::UniverseDiscovery(UniverseDiscoveryPacket {
                source_name: "secure",
                page: 0,
                last_page: 0,
                universes: UniverseList::from_bytes(&UNIVERSES),
            }),
        }
    }

    /// Serializes and seals `packet`, returning the buffer and both lengths.
    fn sealed(packet: &Packet<'_>, mode: SecureMode) -> ([u8; MAX_PACKET_SIZE], usize, usize) {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let plain_len = packet.serialize(&mut buf).unwrap();
        let len = Sealer::new(SecurityKey::new(KEY), mode).seal(&mut buf, plain_len);
        (buf, plain_len, len)
    }

    #[test]
    fn seal_open_parse_roundtrips() {
        for packet in [level_packet(), sync_packet(), discovery_packet()] {
            for mode in [SecureMode::Authenticated, SecureMode::Encrypted] {
                let (mut buf, plain_len, len) = sealed(&packet, mode);
                assert_eq!(len, plain_len + SECURITY_FOOTER_SIZE);
                let n = open(&SecurityKey::new(KEY), &mut buf, len).expect("opens");
                assert_eq!(n, plain_len);
                assert_eq!(Packet::parse(&buf[..n]).unwrap(), packet);
            }
        }
    }

    #[test]
    fn sealed_packet_is_rejected_by_legacy_parse() {
        let (buf, _, len) = sealed(&level_packet(), SecureMode::Authenticated);
        let err = Packet::parse(&buf[..len]).unwrap_err();
        assert!(matches!(
            err.kind,
            CodecErrorKind::UnknownVector {
                layer: VectorLayer::Root,
                ..
            }
        ));
    }

    #[test]
    fn tampering_with_any_byte_fails() {
        for mode in [SecureMode::Authenticated, SecureMode::Encrypted] {
            let (buf, _, len) = sealed(&level_packet(), mode);
            for i in 0..len {
                let mut copy = buf;
                copy[i] ^= 0x01;
                assert_eq!(
                    open(&SecurityKey::new(KEY), &mut copy, len),
                    None,
                    "byte {i}"
                );
            }
        }
    }

    #[test]
    fn wrong_key_fails() {
        let (mut buf, _, len) = sealed(&level_packet(), SecureMode::Encrypted);
        assert_eq!(open(&SecurityKey::new([8; 16]), &mut buf, len), None);
    }

    #[test]
    fn plain_packet_is_not_opened() {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let len = level_packet().serialize(&mut buf).unwrap();
        assert_eq!(open(&SecurityKey::new(KEY), &mut buf, len), None);
    }

    #[test]
    fn encrypted_mode_hides_only_slots() {
        let mut plain = [0u8; MAX_PACKET_SIZE];
        let plain_len = level_packet().serialize(&mut plain).unwrap();
        let (buf, _, _) = sealed(&level_packet(), SecureMode::Encrypted);
        // Past the root vector and length, the header is unchanged...
        assert_eq!(buf[22..DATA_HEADER_SIZE], plain[22..DATA_HEADER_SIZE]);
        // ...but the slots are not.
        assert_ne!(
            buf[DATA_HEADER_SIZE..plain_len],
            plain[DATA_HEADER_SIZE..plain_len]
        );
        assert_eq!(
            read_u32(&buf, ROOT_VECTOR_OFFSET),
            VECTOR_ROOT_E131_DATA | ENCRYPT_FLAG
        );
    }

    #[test]
    fn extended_packets_are_only_authenticated() {
        let (buf, _, _) = sealed(&sync_packet(), SecureMode::Encrypted);
        assert_eq!(
            read_u32(&buf, ROOT_VECTOR_OFFSET),
            VECTOR_ROOT_E131_EXTENDED | AUTH_FLAG
        );
    }

    #[test]
    fn nonce_counter_increments() {
        let mut sealer = Sealer::new(SecurityKey::new(KEY), SecureMode::Authenticated);
        let mut nonces = [[0u8; NONCE_SIZE]; 2];
        for nonce in &mut nonces {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            let n = level_packet().serialize(&mut buf).unwrap();
            let len = sealer.seal(&mut buf, n);
            nonce.copy_from_slice(&buf[len - SECURITY_FOOTER_SIZE..][..NONCE_SIZE]);
        }
        assert_eq!(nonces[0][11], 0);
        assert_eq!(nonces[1][11], 1);
    }
}
