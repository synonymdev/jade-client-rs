use crate::error::{rpc_code, JadeError};
use crate::protocol::{
    classify, decode_reply, encode_request, result_bool, result_bytes, result_text, try_take_frame,
    JadeReply, ReplyMatch, RequestIds, MAX_FRAME_BYTES,
};
use serde::Serialize;

// ============================================================================
// Helpers
// ============================================================================

/// Encode a CBOR map from `(key, value)` pairs.
fn cbor_map(entries: Vec<(&str, ciborium::Value)>) -> Vec<u8> {
    let value = ciborium::Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (ciborium::Value::Text(key.to_string()), value))
            .collect(),
    );
    let mut encoded = Vec::new();
    ciborium::into_writer(&value, &mut encoded).unwrap();
    encoded
}

fn text(value: &str) -> ciborium::Value {
    ciborium::Value::Text(value.to_string())
}

fn int(value: i64) -> ciborium::Value {
    ciborium::Value::Integer(value.into())
}

fn reply_frame(id: &str, result: ciborium::Value) -> Vec<u8> {
    cbor_map(vec![("id", text(id)), ("result", result)])
}

fn error_frame(id: &str, code: i64, message: &str) -> Vec<u8> {
    cbor_map(vec![
        ("id", text(id)),
        (
            "error",
            ciborium::Value::Map(vec![
                (text("code"), int(code)),
                (text("message"), text(message)),
            ]),
        ),
    ])
}

// ============================================================================
// Byte string encoding
//
// This is the single easiest thing to get silently wrong. serde encodes a plain
// `Vec<u8>` as a CBOR array of integers, but Jade reads `psbt` and `entropy`
// with `rpc_get_bytes_ptr`, which requires major type 2. Without
// `#[serde(with = "serde_bytes")]` the device rejects every sign_psbt and
// add_entropy with BAD_PARAMETERS, and nothing catches it until real hardware.
// ============================================================================

#[derive(Serialize)]
struct BytesParams {
    #[serde(with = "serde_bytes")]
    psbt: Vec<u8>,
}

#[derive(Serialize)]
struct NaiveBytesParams {
    psbt: Vec<u8>,
}

/// Locate the CBOR header byte immediately following the text key `psbt`.
fn byte_after_psbt_key(encoded: &[u8]) -> u8 {
    // "psbt" as a CBOR text string of length 4 is 0x64 followed by the ASCII.
    let key = [0x64, b'p', b's', b'b', b't'];
    let position = encoded
        .windows(key.len())
        .position(|window| window == key)
        .expect("psbt key not found in encoding");
    encoded[position + key.len()]
}

#[test]
fn binary_params_encode_as_cbor_byte_strings() {
    let params = BytesParams {
        psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
    };
    let encoded = encode_request("1", "sign_psbt", Some(params)).unwrap();

    // Major type 2 (byte string) occupies 0x40..=0x5f.
    let header = byte_after_psbt_key(&encoded);
    assert!(
        (0x40..=0x5f).contains(&header),
        "expected a byte string header, got {header:#04x}"
    );
}

#[test]
fn binary_params_without_serde_bytes_would_encode_as_an_array() {
    // Guards the reason the annotation exists. If ciborium ever started writing
    // byte strings for a plain Vec<u8>, this test would fail and the annotation
    // could be revisited.
    let params = NaiveBytesParams {
        psbt: vec![0x70, 0x73, 0x62, 0x74, 0xff],
    };
    let encoded = encode_request("1", "sign_psbt", Some(params)).unwrap();

    // Major type 4 (array) occupies 0x80..=0x9f.
    let header = byte_after_psbt_key(&encoded);
    assert!(
        (0x80..=0x9f).contains(&header),
        "expected an array header, got {header:#04x}"
    );
}

#[test]
fn absent_params_are_omitted_rather_than_encoded_as_null() {
    // Jade's typed getters treat a CBOR null as a missing value and then fail
    // with BAD_PARAMETERS, so the key must not be present at all.
    let encoded = encode_request("7", "ping", Option::<()>::None).unwrap();
    assert!(
        !encoded
            .windows(6)
            .any(|w| w == [0x66, b'p', b'a', b'r', b'a', b'm']),
        "params key should be absent"
    );
    let reply: JadeReply = decode_reply(&encoded).unwrap();
    assert_eq!(reply.id.as_deref(), Some("7"));
}

// ============================================================================
// Framing
// ============================================================================

#[test]
fn a_frame_split_across_reads_reassembles() {
    let frame = reply_frame("1", text("xpub"));
    let mut buf = Vec::new();

    for chunk in frame.chunks(3) {
        // Every partial state must report "need more bytes", never a frame.
        if buf.len() + chunk.len() < frame.len() {
            buf.extend_from_slice(chunk);
            assert!(try_take_frame(&mut buf).unwrap().is_none());
        } else {
            buf.extend_from_slice(chunk);
        }
    }

    let taken = try_take_frame(&mut buf).unwrap().expect("frame");
    assert_eq!(taken, frame);
    assert!(buf.is_empty());
}

#[test]
fn two_frames_in_one_read_are_decoded_separately() {
    let first = reply_frame("1", text("one"));
    let second = reply_frame("2", text("two"));
    let mut buf = [first.clone(), second.clone()].concat();

    assert_eq!(try_take_frame(&mut buf).unwrap().unwrap(), first);
    assert_eq!(try_take_frame(&mut buf).unwrap().unwrap(), second);
    assert!(try_take_frame(&mut buf).unwrap().is_none());
}

#[test]
fn an_empty_buffer_needs_more_bytes() {
    let mut buf = Vec::new();
    assert!(try_take_frame(&mut buf).unwrap().is_none());
}

#[test]
fn a_corrupt_length_header_is_capped_rather_than_buffered_forever() {
    // 0x5b announces a byte string whose length is the next eight bytes, here
    // nearly 2^64. skip() will report end of input on every call, so without a
    // cap the read buffer would grow without bound.
    let mut buf = vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert!(try_take_frame(&mut buf).unwrap().is_none());

    buf.extend(std::iter::repeat_n(0u8, MAX_FRAME_BYTES + 1));
    let error = try_take_frame(&mut buf).unwrap_err();
    assert!(matches!(error, JadeError::ProtocolError { .. }));
    assert!(
        buf.is_empty(),
        "buffer must be cleared on a framing failure"
    );
}

#[test]
fn malformed_cbor_errors_rather_than_returning_a_truncated_frame() {
    // 0x1f is a reserved additional-information value for major type 0.
    let mut buf = vec![0x1f, 0x00, 0x00];
    let error = try_take_frame(&mut buf).unwrap_err();
    assert!(matches!(error, JadeError::ProtocolError { .. }));
    assert!(buf.is_empty());
}

// ============================================================================
// Reply correlation
// ============================================================================

#[test]
fn a_log_frame_carrying_no_id_is_ignored() {
    // The device emits these unsolicited on the same stream.
    let frame = cbor_map(vec![(
        "log",
        ciborium::Value::Bytes(b"I (123) main: boot".to_vec()),
    )]);
    let reply = decode_reply(&frame).unwrap();
    assert!(reply.id.is_none());
    assert!(matches!(classify(reply, "1"), ReplyMatch::Ignore));
}

#[test]
fn a_stale_reply_is_ignored_rather_than_failing_the_next_request() {
    let reply = decode_reply(&reply_frame("1", text("old"))).unwrap();
    assert!(matches!(classify(reply, "2"), ReplyMatch::Ignore));
}

#[test]
fn a_matching_reply_is_delivered() {
    let reply = decode_reply(&reply_frame("2", text("xpub"))).unwrap();
    match classify(reply, "2") {
        ReplyMatch::Matched(reply) => {
            assert_eq!(result_text(&reply.result.unwrap()).unwrap(), "xpub");
        }
        other => panic!("expected a match, got {other:?}"),
    }
}

#[test]
fn an_unattributed_error_resolves_the_outstanding_request() {
    // Jade replies with id "00" when it rejects a message before it can recover
    // the request id, for example an oversize or malformed request. Ignoring
    // these would turn every such rejection into a full length timeout.
    let frame = error_frame(
        crate::protocol::UNATTRIBUTED_ID,
        rpc_code::INVALID_REQUEST,
        "Invalid RPC Request message",
    );
    let reply = decode_reply(&frame).unwrap();
    match classify(reply, "7") {
        ReplyMatch::Unattributed(error) => {
            assert_eq!(error.code, rpc_code::INVALID_REQUEST);
        }
        other => panic!("expected an unattributed error, got {other:?}"),
    }
}

#[test]
fn an_unattributed_frame_without_an_error_member_is_ignored() {
    let reply = decode_reply(&reply_frame(crate::protocol::UNATTRIBUTED_ID, text("x"))).unwrap();
    assert!(matches!(classify(reply, "7"), ReplyMatch::Ignore));
}

// ============================================================================
// Error mapping
// ============================================================================

#[test]
fn rpc_error_codes_map_to_typed_errors() {
    let cases = [
        (rpc_code::USER_CANCELLED, JadeError::UserCancelled),
        (rpc_code::HW_LOCKED, JadeError::DeviceLocked),
    ];
    for (code, expected) in cases {
        let reply = decode_reply(&error_frame("1", code, "denied")).unwrap();
        assert_eq!(reply.into_result("1.0.0").unwrap_err(), expected);
    }

    let reply = decode_reply(&error_frame("1", rpc_code::NETWORK_MISMATCH, "wrong net")).unwrap();
    assert!(matches!(
        reply.into_result("1.0.0").unwrap_err(),
        JadeError::NetworkMismatch { .. }
    ));

    // An old device answering UNKNOWN_METHOD is reporting its age, not a host
    // bug, so it must not surface as a generic protocol error.
    let reply = decode_reply(&error_frame("1", rpc_code::UNKNOWN_METHOD, "nope")).unwrap();
    assert!(matches!(
        reply.into_result("1.0.30").unwrap_err(),
        JadeError::UnsupportedFirmware { .. }
    ));

    let reply = decode_reply(&error_frame("1", rpc_code::INVALID_REQUEST, "bad")).unwrap();
    assert!(matches!(
        reply.into_result("1.0.0").unwrap_err(),
        JadeError::ProtocolError { .. }
    ));

    let reply = decode_reply(&error_frame("1", -32099, "novel")).unwrap();
    assert!(matches!(
        reply.into_result("1.0.0").unwrap_err(),
        JadeError::DeviceError { .. }
    ));
}

#[test]
fn a_reply_with_neither_result_nor_error_is_a_protocol_error() {
    let reply = decode_reply(&cbor_map(vec![("id", text("1"))])).unwrap();
    assert!(matches!(
        reply.into_result("1.0.0").unwrap_err(),
        JadeError::ProtocolError { .. }
    ));
}

// ============================================================================
// Result readers
// ============================================================================

#[test]
fn byte_string_results_are_read_as_bytes() {
    // sign_psbt returns a CBOR byte string. Going through
    // Value::deserialized::<Vec<u8>>() would fail here, because the Value
    // deserializer maps deserialize_seq onto Value::Array only.
    let frame = reply_frame("1", ciborium::Value::Bytes(vec![0x70, 0x73, 0x62, 0x74]));
    let reply = decode_reply(&frame).unwrap();
    let value = reply.into_result("1.0.0").unwrap();
    assert_eq!(result_bytes(&value).unwrap(), vec![0x70, 0x73, 0x62, 0x74]);
}

#[test]
fn boolean_and_text_results_are_read() {
    let reply = decode_reply(&reply_frame("1", ciborium::Value::Bool(true))).unwrap();
    assert!(result_bool(&reply.into_result("1.0.0").unwrap()).unwrap());

    let reply = decode_reply(&reply_frame("1", text("tpub..."))).unwrap();
    assert_eq!(
        result_text(&reply.into_result("1.0.0").unwrap()).unwrap(),
        "tpub..."
    );
}

#[test]
fn a_wrongly_typed_result_is_a_protocol_error() {
    let reply = decode_reply(&reply_frame("1", int(5))).unwrap();
    let value = reply.into_result("1.0.0").unwrap();
    assert!(matches!(
        result_text(&value).unwrap_err(),
        JadeError::ProtocolError { .. }
    ));
}

#[test]
fn sequenced_replies_expose_seqnum_and_seqlen() {
    let frame = cbor_map(vec![
        ("id", text("1")),
        ("result", ciborium::Value::Bytes(vec![1, 2, 3])),
        ("seqnum", int(1)),
        ("seqlen", int(3)),
    ]);
    let reply = decode_reply(&frame).unwrap();
    assert_eq!(reply.seqnum, Some(1));
    assert_eq!(reply.seqlen, Some(3));
}

// ============================================================================
// Request ids
// ============================================================================

#[test]
fn request_ids_are_sequential_per_connection_and_fit_the_device_limit() {
    let mut ids = RequestIds::new();
    assert_eq!(ids.next_id(), "1");
    assert_eq!(ids.next_id(), "2");
    assert_eq!(ids.next_id(), "3");

    // Two connections do not share a counter, so ids stay deterministic in a
    // test process that runs many of them concurrently.
    let mut other = RequestIds::new();
    assert_eq!(other.next_id(), "1");
}

#[test]
fn request_ids_never_exceed_the_sixteen_character_limit() {
    let mut ids = RequestIds::new();
    for _ in 0..1000 {
        let id = ids.next_id();
        assert!(!id.is_empty());
        assert!(id.len() < 16, "id {id} is too long for Jade");
    }
}

// ============================================================================
// Path validation
//
// DerivationPath::from_str alone accepts "" as the master path and accepts a
// path with no "m/" prefix, either of which would be a silent footgun.
// ============================================================================

mod paths {
    use crate::error::JadeError;
    use crate::path;

    #[test]
    fn a_valid_path_lowers_to_the_wire_representation() {
        assert_eq!(
            path::to_wire("m/84'/0'/0'/0/0", false).unwrap(),
            vec![2147483732, 2147483648, 2147483648, 0, 0]
        );
        // The 'h' hardened notation is equivalent to an apostrophe.
        assert_eq!(
            path::to_wire("m/84h/1h/0h", false).unwrap(),
            vec![2147483732, 2147483649, 2147483648]
        );
    }

    #[test]
    fn the_empty_path_is_rejected_unless_explicitly_allowed() {
        // Signing with the master key because a caller passed "" is exactly the
        // outcome this guards against.
        assert!(matches!(
            path::validate("", false).unwrap_err(),
            JadeError::InvalidPath { .. }
        ));
        assert!(matches!(
            path::validate("m", false).unwrap_err(),
            JadeError::InvalidPath { .. }
        ));
        assert!(matches!(
            path::validate("m/", false).unwrap_err(),
            JadeError::InvalidPath { .. }
        ));

        // The master-fingerprint lookup opts in deliberately.
        assert!(path::validate("m", true).is_ok());
        assert_eq!(path::to_wire("m", true).unwrap(), Vec::<u32>::new());
    }

    #[test]
    fn a_path_without_the_m_prefix_is_rejected() {
        assert!(matches!(
            path::validate("84'/0'/0'", false).unwrap_err(),
            JadeError::InvalidPath { .. }
        ));
    }

    #[test]
    fn malformed_and_overdeep_paths_are_rejected() {
        for bad in [
            "m/84'/x/0'",
            "m/84'//0'",
            "m/84'/0'/",
            "n/84'/0'",
            "m/84'/0'/0'/0/0/0/0/0/0",
        ] {
            assert!(
                matches!(
                    path::validate(bad, false),
                    Err(JadeError::InvalidPath { .. })
                ),
                "{bad} should have been rejected"
            );
        }
    }

    #[test]
    fn the_purpose_element_is_readable_for_variant_cross_checks() {
        assert_eq!(path::purpose("m/84'/0'/0'/0/0"), Some(84));
        assert_eq!(path::purpose("m/44'/0'/0'"), Some(44));
        assert_eq!(path::purpose("m"), None);
    }
}

// ============================================================================
// Types
// ============================================================================

mod device_types {
    use crate::types::*;

    #[test]
    fn networks_use_jades_own_names() {
        assert_eq!(JadeNetwork::Mainnet.wire_name(), "mainnet");
        assert_eq!(JadeNetwork::Testnet.wire_name(), "testnet");
        // Jade calls regtest "localtest".
        assert_eq!(JadeNetwork::Regtest.wire_name(), "localtest");
    }

    #[test]
    fn variants_map_to_purposes_and_descriptor_strings() {
        let cases = [
            (JadeAddressVariant::Pkh, 44, "pkh(k)"),
            (JadeAddressVariant::ShWpkh, 49, "sh(wpkh(k))"),
            (JadeAddressVariant::Wpkh, 84, "wpkh(k)"),
            (JadeAddressVariant::Tr, 86, "tr(k)"),
        ];
        for (variant, purpose, wire) in cases {
            assert_eq!(variant.purpose(), purpose);
            assert_eq!(variant.wire_name(), wire);
            assert_eq!(JadeAddressVariant::from_purpose(purpose), Some(variant));
        }
        assert_eq!(JadeAddressVariant::from_purpose(48), None);
    }

    #[test]
    fn version_info_maps_from_the_screaming_snake_wire_shape() {
        // Deriving Deserialize straight onto the FFI record would yield None for
        // every field, since the wire uses JADE_VERSION rather than jade_version.
        let wire = cbor_version_info("1.0.34", "LOCKED");
        let parsed: WireVersionInfo = ciborium::from_reader(wire.as_slice()).unwrap();
        let info = JadeVersionInfo::from(parsed);

        assert_eq!(info.jade_version, "1.0.34");
        assert_eq!(info.jade_state, JadeState::Locked);
        assert_eq!(info.jade_networks.as_deref(), Some("TEST"));
        assert_eq!(info.jade_has_pin, Some(true));
        assert_eq!(info.battery_status, Some(4));
    }

    #[test]
    fn an_unrecognised_state_string_does_not_fail_the_decode() {
        let wire = cbor_version_info("9.9.9", "SOMETHING_NEW");
        let parsed: WireVersionInfo = ciborium::from_reader(wire.as_slice()).unwrap();
        assert_eq!(JadeVersionInfo::from(parsed).jade_state, JadeState::Unknown);
    }

    #[test]
    fn every_documented_state_string_maps() {
        for (wire, expected) in [
            ("UNINIT", JadeState::Uninit),
            ("UNSAVED", JadeState::Unsaved),
            ("LOCKED", JadeState::Locked),
            ("READY", JadeState::Ready),
            ("TEMP", JadeState::Temp),
        ] {
            let encoded = cbor_version_info("1.0.34", wire);
            let parsed: WireVersionInfo = ciborium::from_reader(encoded.as_slice()).unwrap();
            assert_eq!(JadeVersionInfo::from(parsed).jade_state, expected);
        }
    }

    #[test]
    fn ping_status_maps_from_the_wire_integer() {
        assert_eq!(JadePingStatus::from_wire(0), JadePingStatus::Idle);
        assert_eq!(JadePingStatus::from_wire(1), JadePingStatus::Busy);
        assert_eq!(
            JadePingStatus::from_wire(2),
            JadePingStatus::AwaitingUserInput
        );
    }

    fn cbor_version_info(version: &str, state: &str) -> Vec<u8> {
        let text = |v: &str| ciborium::Value::Text(v.to_string());
        let value = ciborium::Value::Map(vec![
            (text("JADE_VERSION"), text(version)),
            (text("JADE_STATE"), text(state)),
            (text("JADE_NETWORKS"), text("TEST")),
            (text("JADE_HAS_PIN"), ciborium::Value::Bool(true)),
            (text("BOARD_TYPE"), text("JADE_V2")),
            (text("BATTERY_STATUS"), ciborium::Value::Integer(4.into())),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).unwrap();
        encoded
    }
}

// ============================================================================
// Transport and the request/reply loop
//
// Driven by a scripted mock device, so framing, correlation, fragment
// reassembly, cancellation and poisoning are all covered without hardware.
// ============================================================================

mod connection {
    use super::cbor_map;
    use crate::error::JadeError;
    use crate::transport::{JadeConnection, JadeTransport};
    use async_trait::async_trait;
    use serde::Deserialize;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    pub(super) fn text(value: &str) -> ciborium::Value {
        ciborium::Value::Text(value.to_string())
    }

    pub(super) fn int(value: i64) -> ciborium::Value {
        ciborium::Value::Integer(value.into())
    }

    /// The fields of a request the mock needs in order to answer it.
    #[derive(Debug, Deserialize)]
    pub(super) struct SeenRequest {
        pub(super) id: String,
        pub(super) method: String,
    }

    pub(super) type Responder = Box<dyn Fn(&SeenRequest) -> Vec<u8> + Send + Sync>;

    /// A scripted device.
    ///
    /// Each write consumes one responder, which builds the reply bytes from the
    /// request that triggered it. Replies are queued and handed out by
    /// `read_some` in whatever chunk sizes the test asked for, so a frame split
    /// across reads is exercised end to end.
    pub(super) struct MockTransport {
        responders: Mutex<VecDeque<Responder>>,
        pending: Mutex<VecDeque<Vec<u8>>>,
        writes: Mutex<Vec<Vec<u8>>>,
        read_chunk: usize,
        read_delay: Duration,
        fail_next_read: AtomicBool,
        /// Armed with the connection's abort flag. The next read sets it and
        /// then fails, which is what a cancel looks like from inside
        /// `read_some`: the flag and the closed link arrive together.
        abort_during_read: Mutex<Option<Arc<AtomicBool>>>,
        closed: AtomicBool,
    }

    impl MockTransport {
        pub(super) fn new(responders: Vec<Responder>) -> Arc<Self> {
            Arc::new(Self {
                responders: Mutex::new(responders.into()),
                pending: Mutex::new(VecDeque::new()),
                writes: Mutex::new(Vec::new()),
                read_chunk: usize::MAX,
                read_delay: Duration::ZERO,
                fail_next_read: AtomicBool::new(false),
                abort_during_read: Mutex::new(None),
                closed: AtomicBool::new(false),
            })
        }

        fn with_read_chunk(responders: Vec<Responder>, read_chunk: usize) -> Arc<Self> {
            let mut mock = Self {
                responders: Mutex::new(responders.into()),
                pending: Mutex::new(VecDeque::new()),
                writes: Mutex::new(Vec::new()),
                read_chunk,
                read_delay: Duration::ZERO,
                fail_next_read: AtomicBool::new(false),
                abort_during_read: Mutex::new(None),
                closed: AtomicBool::new(false),
            };
            mock.read_chunk = read_chunk;
            Arc::new(mock)
        }

        fn with_read_delay(responders: Vec<Responder>, read_delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                responders: Mutex::new(responders.into()),
                pending: Mutex::new(VecDeque::new()),
                writes: Mutex::new(Vec::new()),
                read_chunk: usize::MAX,
                read_delay,
                fail_next_read: AtomicBool::new(false),
                abort_during_read: Mutex::new(None),
                closed: AtomicBool::new(false),
            })
        }

        /// Make the next read behave like one that a cancel interrupted.
        fn abort_during_read(&self, aborted: &Arc<AtomicBool>) {
            *self.abort_during_read.lock().unwrap() = Some(Arc::clone(aborted));
        }

        pub(super) fn write_count(&self) -> usize {
            self.writes.lock().unwrap().len()
        }

        fn is_closed(&self) -> bool {
            self.closed.load(Ordering::SeqCst)
        }

        /// The raw bytes of the nth request, for byte level assertions.
        pub(super) fn writes_for_test(&self, index: usize) -> Vec<u8> {
            self.writes.lock().unwrap()[index].clone()
        }

        pub(super) fn seen(&self, index: usize) -> SeenRequest {
            let writes = self.writes.lock().unwrap();
            ciborium::from_reader(writes[index].as_slice()).unwrap()
        }
    }

    #[async_trait]
    impl JadeTransport for MockTransport {
        async fn write_all(&self, data: Vec<u8>) -> Result<(), JadeError> {
            let request: SeenRequest = ciborium::from_reader(data.as_slice())
                .map_err(|error| JadeError::protocol(format!("mock: {error}")))?;
            self.writes.lock().unwrap().push(data);

            if let Some(responder) = self.responders.lock().unwrap().pop_front() {
                let reply = responder(&request);
                if !reply.is_empty() {
                    self.pending.lock().unwrap().push_back(reply);
                }
            }
            Ok(())
        }

        async fn read_some(&self, timeout: Duration) -> Result<Vec<u8>, JadeError> {
            if let Some(aborted) = self.abort_during_read.lock().unwrap().take() {
                aborted.store(true, Ordering::SeqCst);
                return Err(JadeError::DeviceDisconnected);
            }
            if self.fail_next_read.swap(false, Ordering::SeqCst) {
                return Err(JadeError::DeviceDisconnected);
            }
            if !self.read_delay.is_zero() {
                tokio::time::sleep(self.read_delay.min(timeout)).await;
                if self.read_delay > timeout {
                    return Ok(Vec::new());
                }
            }
            let mut pending = self.pending.lock().unwrap();
            let Some(mut next) = pending.pop_front() else {
                return Ok(Vec::new());
            };
            if self.read_chunk < next.len() {
                let rest = next.split_off(self.read_chunk);
                pending.push_front(rest);
            }
            Ok(next)
        }

        async fn close(&self) -> Result<(), JadeError> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn ok_reply(result: ciborium::Value) -> Responder {
        Box::new(move |request: &SeenRequest| {
            cbor_map(vec![("id", text(&request.id)), ("result", result.clone())])
        })
    }

    fn version_info() -> ciborium::Value {
        ciborium::Value::Map(vec![
            (text("JADE_VERSION"), text("1.0.34")),
            (text("JADE_STATE"), text("READY")),
        ])
    }

    pub(super) fn connect(mock: Arc<MockTransport>) -> (JadeConnection, Arc<AtomicBool>) {
        let aborted = Arc::new(AtomicBool::new(false));
        let connection = JadeConnection::new(mock, Arc::clone(&aborted));
        (connection, aborted)
    }

    #[tokio::test]
    async fn failed_initialization_closes_the_transport() {
        let add_entropy_error: Responder = Box::new(|request: &SeenRequest| {
            cbor_map(vec![
                ("id", text(&request.id)),
                (
                    "error",
                    ciborium::Value::Map(vec![
                        (text("code"), int(-32602)),
                        (text("message"), text("bad entropy")),
                    ]),
                ),
            ])
        });
        let mock = MockTransport::new(vec![ok_reply(version_info()), add_entropy_error]);

        let error = crate::Jade::connect(Arc::clone(&mock) as Arc<dyn JadeTransport>)
            .await
            .unwrap_err();

        assert!(matches!(error, JadeError::DeviceError { .. }));
        assert!(mock.is_closed());
    }

    #[tokio::test]
    async fn a_request_gets_its_reply() {
        let mock = MockTransport::new(vec![ok_reply(text("tpubDC"))]);
        let (mut connection, _) = connect(Arc::clone(&mock));

        let reply = connection
            .exchange("get_xpub", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            crate::protocol::result_text(&reply.into_result("1.0.0").unwrap()).unwrap(),
            "tpubDC"
        );
        assert_eq!(mock.seen(0).method, "get_xpub");
    }

    #[tokio::test]
    async fn a_reply_arriving_one_byte_at_a_time_still_decodes() {
        let mock = MockTransport::with_read_chunk(vec![ok_reply(text("tpubDC"))], 1);
        let (mut connection, _) = connect(mock);

        let reply = connection
            .exchange("get_xpub", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            crate::protocol::result_text(&reply.into_result("1.0.0").unwrap()).unwrap(),
            "tpubDC"
        );
    }

    #[tokio::test]
    async fn an_unsolicited_log_frame_is_skipped() {
        // The device interleaves log frames with replies on the same stream.
        let responder: Responder = Box::new(|request: &SeenRequest| {
            let log = cbor_map(vec![(
                "log",
                ciborium::Value::Bytes(b"I (1) main: hello".to_vec()),
            )]);
            let reply = cbor_map(vec![("id", text(&request.id)), ("result", text("ok"))]);
            [log, reply].concat()
        });
        let mock = MockTransport::new(vec![responder]);
        let (mut connection, _) = connect(mock);

        let reply = connection
            .exchange("ping", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap();
        assert!(reply.result.is_some());
    }

    #[tokio::test]
    async fn an_unattributed_error_resolves_the_request_instead_of_timing_out() {
        // Jade answers with id "00" when it rejects a message before recovering
        // its id. Discarding that would strand the caller until the deadline.
        let responder: Responder = Box::new(|_: &SeenRequest| {
            cbor_map(vec![
                ("id", text("00")),
                (
                    "error",
                    ciborium::Value::Map(vec![
                        (text("code"), int(-32600)),
                        (text("message"), text("Invalid RPC Request message")),
                    ]),
                ),
            ])
        });
        let mock = MockTransport::new(vec![responder]);
        let (mut connection, _) = connect(mock);

        let error = connection
            .exchange("sign_psbt", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(error, JadeError::ProtocolError { .. }));
    }

    #[tokio::test]
    async fn a_multi_fragment_reply_is_reassembled_in_order() {
        // sign_psbt splits long replies across get_extended_data calls. Each of
        // those carries a fresh id while origid names the original request, so
        // the id being matched changes every round.
        let fragment = |bytes: Vec<u8>, seqnum: i64, seqlen: i64| -> Responder {
            Box::new(move |request: &SeenRequest| {
                cbor_map(vec![
                    ("id", text(&request.id)),
                    ("result", ciborium::Value::Bytes(bytes.clone())),
                    ("seqnum", int(seqnum)),
                    ("seqlen", int(seqlen)),
                ])
            })
        };
        let mock = MockTransport::new(vec![
            fragment(vec![1, 2, 3], 1, 3),
            fragment(vec![4, 5, 6], 2, 3),
            fragment(vec![7, 8], 3, 3),
        ]);
        let (mut connection, _) = connect(Arc::clone(&mock));

        let payload = connection
            .exchange_reassembled("sign_psbt", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap();

        assert_eq!(payload, vec![1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(mock.write_count(), 3);

        // The follow-ups are get_extended_data, and each has its own id rather
        // than reusing the original.
        let original = mock.seen(0);
        let second = mock.seen(1);
        assert_eq!(second.method, "get_extended_data");
        assert_ne!(second.id, original.id);
        assert_ne!(mock.seen(2).id, second.id);
    }

    #[tokio::test]
    async fn a_single_fragment_reply_needs_no_follow_up() {
        let responder: Responder = Box::new(|request: &SeenRequest| {
            cbor_map(vec![
                ("id", text(&request.id)),
                ("result", ciborium::Value::Bytes(vec![9, 9])),
                ("seqnum", int(1)),
                ("seqlen", int(1)),
            ])
        });
        let mock = MockTransport::new(vec![responder]);
        let (mut connection, _) = connect(Arc::clone(&mock));

        let payload = connection
            .exchange_reassembled("sign_psbt", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(payload, vec![9, 9]);
        assert_eq!(mock.write_count(), 1);
    }

    #[tokio::test]
    async fn a_fragment_with_the_wrong_sequence_number_is_rejected() {
        let mock = MockTransport::new(vec![
            Box::new(|request: &SeenRequest| {
                cbor_map(vec![
                    ("id", text(&request.id)),
                    ("result", ciborium::Value::Bytes(vec![1])),
                    ("seqnum", int(1)),
                    ("seqlen", int(3)),
                ])
            }),
            Box::new(|request: &SeenRequest| {
                cbor_map(vec![
                    ("id", text(&request.id)),
                    ("result", ciborium::Value::Bytes(vec![2])),
                    ("seqnum", int(3)), // should be 2
                    ("seqlen", int(3)),
                ])
            }),
        ]);
        let (mut connection, _) = connect(mock);

        let error = connection
            .exchange_reassembled("sign_psbt", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(matches!(error, JadeError::ProtocolError { .. }));
    }

    #[tokio::test]
    async fn an_excessive_fragment_count_is_rejected() {
        let responder: Responder = Box::new(|request: &SeenRequest| {
            cbor_map(vec![
                ("id", text(&request.id)),
                ("result", ciborium::Value::Bytes(vec![1])),
                ("seqnum", int(1)),
                (
                    "seqlen",
                    int(i64::from(crate::transport::MAX_REPLY_FRAGMENTS + 1)),
                ),
            ])
        });
        let mock = MockTransport::new(vec![responder]);
        let (mut connection, _) = connect(Arc::clone(&mock));

        let error = connection
            .exchange_reassembled("sign_psbt", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(matches!(error, JadeError::ProtocolError { .. }));
        assert_eq!(mock.write_count(), 1);
    }

    #[tokio::test]
    async fn an_oversized_reassembled_reply_is_rejected() {
        let fragment = |seqnum: i64| -> Responder {
            Box::new(move |request: &SeenRequest| {
                cbor_map(vec![
                    ("id", text(&request.id)),
                    (
                        "result",
                        ciborium::Value::Bytes(vec![
                            0;
                            crate::transport::MAX_REASSEMBLED_BYTES / 2 + 1
                        ]),
                    ),
                    ("seqnum", int(seqnum)),
                    ("seqlen", int(2)),
                ])
            })
        };
        let mock = MockTransport::new(vec![fragment(1), fragment(2)]);
        let (mut connection, _) = connect(mock);

        let error = connection
            .exchange_reassembled("sign_psbt", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap_err();

        assert!(matches!(error, JadeError::ProtocolError { .. }));
    }

    #[tokio::test]
    async fn fragments_share_one_operation_deadline() {
        let fragment = |bytes: Vec<u8>, seqnum: i64, seqlen: i64| -> Responder {
            Box::new(move |request: &SeenRequest| {
                cbor_map(vec![
                    ("id", text(&request.id)),
                    ("result", ciborium::Value::Bytes(bytes.clone())),
                    ("seqnum", int(seqnum)),
                    ("seqlen", int(seqlen)),
                ])
            })
        };
        let mock = MockTransport::with_read_delay(
            vec![fragment(vec![1], 1, 2), fragment(vec![2], 2, 2)],
            Duration::from_millis(60),
        );
        let (mut connection, _) = connect(mock);
        let started = std::time::Instant::now();

        let error = connection
            .exchange_reassembled("sign_psbt", Option::<()>::None, Duration::from_millis(100))
            .await
            .unwrap_err();

        assert_eq!(error, JadeError::Timeout);
        assert!(started.elapsed() < Duration::from_millis(180));
    }

    #[tokio::test]
    async fn a_transport_error_poisons_the_connection() {
        // A failure mid frame leaves no way to find the next boundary, so the
        // connection must refuse further work rather than desynchronise.
        let mock = MockTransport::new(vec![ok_reply(text("never read"))]);
        mock.fail_next_read.store(true, Ordering::SeqCst);
        let (mut connection, _) = connect(Arc::clone(&mock));

        let error = connection
            .exchange("ping", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(error, JadeError::DeviceDisconnected);

        let next = connection
            .exchange("ping", Option::<()>::None, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert_eq!(next, JadeError::DeviceDisconnected);
    }

    #[tokio::test]
    async fn cancelling_returns_promptly_rather_than_waiting_out_the_deadline() {
        // Jade has no cancel RPC, so aborting is how the application implements
        // a cancel button on a signing screen. A ten minute deadline must not
        // mean a ten minute wait.
        let mock = MockTransport::new(vec![Box::new(|_: &SeenRequest| Vec::new())]);
        let (mut connection, aborted) = connect(mock);
        aborted.store(true, Ordering::SeqCst);

        let started = std::time::Instant::now();
        let error = connection
            .exchange("sign_psbt", Option::<()>::None, Duration::from_secs(600))
            .await
            .unwrap_err();

        assert_eq!(error, JadeError::UserCancelled);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_cancel_noticed_as_a_transport_error_is_still_a_cancellation() {
        // `cancel` sets the abort flag and closes the link, so a loop parked
        // inside `read_some` sees only the close. That is the common case on
        // Bluetooth, where a read blocks for its timeout, and reporting it as a
        // disconnection would put an error on a screen the user just dismissed.
        let mock = MockTransport::new(vec![Box::new(|_: &SeenRequest| Vec::new())]);
        let (mut connection, aborted) = connect(Arc::clone(&mock));
        mock.abort_during_read(&aborted);

        let error = connection
            .exchange("sign_psbt", Option::<()>::None, Duration::from_secs(600))
            .await
            .unwrap_err();

        assert_eq!(error, JadeError::UserCancelled);
    }

    #[tokio::test]
    async fn a_silent_device_times_out_without_spinning() {
        let mock = MockTransport::new(vec![Box::new(|_: &SeenRequest| Vec::new())]);
        let (mut connection, _) = connect(mock);

        let error = connection
            .exchange("ping", Option::<()>::None, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert_eq!(error, JadeError::Timeout);
    }

    #[tokio::test]
    async fn a_stale_reply_does_not_satisfy_the_next_request() {
        let responder: Responder = Box::new(|_: &SeenRequest| {
            cbor_map(vec![("id", text("999")), ("result", text("stale"))])
        });
        let mock = MockTransport::new(vec![responder]);
        let (mut connection, _) = connect(mock);

        let error = connection
            .exchange("ping", Option::<()>::None, Duration::from_millis(200))
            .await
            .unwrap_err();
        assert_eq!(error, JadeError::Timeout);
    }
}

// ============================================================================
// Pinserver unlock
// ============================================================================

mod unlock {
    use super::cbor_map;
    use super::connection::{connect, int, text, MockTransport, Responder, SeenRequest};
    use crate::error::JadeError;
    use crate::pinserver::{self, PinServerHttp};
    use crate::types::JadeNetwork;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// A pinserver that never touches the network.
    struct FakePinServer {
        response: Mutex<Option<Result<Vec<u8>, JadeError>>>,
        calls: Mutex<Vec<(String, String, Option<String>)>>,
    }

    impl FakePinServer {
        fn returning(body: &str) -> Arc<Self> {
            Arc::new(Self {
                response: Mutex::new(Some(Ok(body.as_bytes().to_vec()))),
                calls: Mutex::new(Vec::new()),
            })
        }

        fn failing() -> Arc<Self> {
            Arc::new(Self {
                response: Mutex::new(Some(Err(JadeError::PinServerError {
                    error_details: "network down".to_string(),
                }))),
                calls: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait]
    impl PinServerHttp for FakePinServer {
        async fn request(
            &self,
            url: &str,
            method: &str,
            body: Option<String>,
        ) -> Result<Vec<u8>, JadeError> {
            self.calls
                .lock()
                .unwrap()
                .push((url.to_string(), method.to_string(), body));
            self.response
                .lock()
                .unwrap()
                .take()
                .unwrap_or(Ok(b"{}".to_vec()))
        }
    }

    struct StalledPinServer;

    #[async_trait]
    impl PinServerHttp for StalledPinServer {
        async fn request(
            &self,
            _url: &str,
            _method: &str,
            _body: Option<String>,
        ) -> Result<Vec<u8>, JadeError> {
            std::future::pending().await
        }
    }

    /// An auth_user reply asking the host to call the pinserver.
    fn http_request_reply(urls: Vec<&str>, on_reply: &str) -> Responder {
        let urls: Vec<String> = urls.into_iter().map(str::to_string).collect();
        let on_reply = on_reply.to_string();
        Box::new(move |request: &SeenRequest| {
            let url_values =
                ciborium::Value::Array(urls.iter().map(|url| text(url)).collect::<Vec<_>>());
            let params = ciborium::Value::Map(vec![
                (text("urls"), url_values),
                (text("method"), text("POST")),
                (text("accept"), text("json")),
                (
                    text("data"),
                    ciborium::Value::Map(vec![(text("data"), text("cGF5bG9hZA=="))]),
                ),
            ]);
            let http_request = ciborium::Value::Map(vec![
                (text("params"), params),
                (text("on-reply"), text(&on_reply)),
            ]);
            cbor_map(vec![
                ("id", text(&request.id)),
                (
                    "result",
                    ciborium::Value::Map(vec![(text("http_request"), http_request)]),
                ),
            ])
        })
    }

    fn bool_reply(value: bool) -> Responder {
        Box::new(move |request: &SeenRequest| {
            cbor_map(vec![
                ("id", text(&request.id)),
                ("result", ciborium::Value::Bool(value)),
            ])
        })
    }

    #[tokio::test]
    async fn an_already_unlocked_device_needs_no_pinserver_call() {
        let mock = MockTransport::new(vec![bool_reply(true)]);
        let (mut connection, _) = connect(Arc::clone(&mock));
        let http = FakePinServer::returning("{}");

        pinserver::run_unlock(
            &mut connection,
            JadeNetwork::Testnet,
            http.as_ref(),
            1_700_000_000,
        )
        .await
        .unwrap();

        assert_eq!(mock.write_count(), 1);
        assert_eq!(mock.seen(0).method, "auth_user");
        assert!(http.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_locked_device_completes_the_pinserver_round_trip() {
        let mock = MockTransport::new(vec![
            http_request_reply(vec!["https://jadepin.blockstream.com/get_pin"], "pin"),
            bool_reply(true),
        ]);
        let (mut connection, _) = connect(Arc::clone(&mock));
        let http = FakePinServer::returning(r#"{"data":"YWJj"}"#);

        pinserver::run_unlock(
            &mut connection,
            JadeNetwork::Mainnet,
            http.as_ref(),
            1_700_000_000,
        )
        .await
        .unwrap();

        // The device saw auth_user then pin.
        assert_eq!(mock.write_count(), 2);
        assert_eq!(mock.seen(1).method, "pin");

        // The payload was rendered as a JSON document, not forwarded as CBOR.
        let calls = http.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, "POST");
        assert_eq!(calls[0].2.as_deref(), Some(r#"{"data":"cGF5bG9hZA=="}"#));
    }

    #[tokio::test]
    async fn a_wrong_pin_is_reported_as_such() {
        let mock = MockTransport::new(vec![
            http_request_reply(vec!["https://jadepin.blockstream.com/get_pin"], "pin"),
            bool_reply(false),
        ]);
        let (mut connection, _) = connect(mock);
        let http = FakePinServer::returning(r#"{"data":"YWJj"}"#);

        let error = pinserver::run_unlock(&mut connection, JadeNetwork::Mainnet, http.as_ref(), 0)
            .await
            .unwrap_err();
        assert_eq!(error, JadeError::InvalidPin);
    }

    #[tokio::test]
    async fn an_http_failure_still_sends_pin_so_the_device_stays_in_step() {
        // The device blocks indefinitely waiting for a pin message. Abandoning
        // the exchange would leave it consuming the next unrelated request as
        // the awaited reply, putting every later call one message out of step.
        let mock = MockTransport::new(vec![
            http_request_reply(vec!["https://jadepin.blockstream.com/get_pin"], "pin"),
            bool_reply(false),
        ]);
        let (mut connection, _) = connect(Arc::clone(&mock));
        let http = FakePinServer::failing();

        let error = pinserver::run_unlock(&mut connection, JadeNetwork::Mainnet, http.as_ref(), 0)
            .await
            .unwrap_err();
        assert_eq!(error, JadeError::InvalidPin);

        assert_eq!(mock.write_count(), 2);
        let sent = mock.seen(1);
        assert_eq!(sent.method, "pin");

        // And it carried no params at all, which is what signals the failure.
        let writes_have_params = {
            let raw: ciborium::Value = {
                let writes = mock.writes_for_test(1);
                ciborium::from_reader(writes.as_slice()).unwrap()
            };
            match raw {
                ciborium::Value::Map(entries) => entries
                    .iter()
                    .any(|(key, _)| key.as_text() == Some("params")),
                _ => panic!("request was not a map"),
            }
        };
        assert!(!writes_have_params, "pin must be sent with no params");
    }

    #[tokio::test]
    async fn a_stalled_pinserver_honours_the_unlock_deadline() {
        let mock = MockTransport::new(vec![http_request_reply(
            vec!["https://jadepin.blockstream.com/get_pin"],
            "pin",
        )]);
        let (mut connection, _) = connect(mock);
        let started = Instant::now();

        let error = pinserver::run_unlock_with_timeout(
            &mut connection,
            JadeNetwork::Mainnet,
            &StalledPinServer,
            0,
            Duration::from_millis(100),
        )
        .await
        .unwrap_err();

        assert_eq!(error, JadeError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(feature = "reqwest-pinserver")]
    #[test]
    fn a_chunk_that_exceeds_the_body_limit_is_rejected_before_append() {
        let mut body = vec![0; 64 * 1024];

        let error = pinserver::append_body_chunk(&mut body, &[1]).unwrap_err();

        assert!(matches!(error, JadeError::PinServerError { .. }));
        assert_eq!(body.len(), 64 * 1024);
    }

    #[tokio::test]
    async fn a_device_naming_a_method_other_than_pin_is_rejected() {
        // on-reply is device supplied. Dispatching on it blindly would let a
        // device make the host invoke any RPC with params of its choosing.
        let mock = MockTransport::new(vec![http_request_reply(
            vec!["https://jadepin.blockstream.com/get_pin"],
            "sign_psbt",
        )]);
        let (mut connection, _) = connect(mock);
        let http = FakePinServer::returning("{}");

        let error = pinserver::run_unlock(&mut connection, JadeNetwork::Mainnet, http.as_ref(), 0)
            .await
            .unwrap_err();
        assert!(matches!(error, JadeError::ProtocolError { .. }));
    }

    #[tokio::test]
    async fn an_onion_url_is_skipped_in_favour_of_the_clearnet_one() {
        // Firmware sends http://<...>.onion/get_pin, so a suffix test on the
        // whole URL would not spot it.
        let mock = MockTransport::new(vec![
            http_request_reply(
                vec![
                    "https://jadepin.blockstream.com/get_pin",
                    "http://abcdefghij.onion/get_pin",
                ],
                "pin",
            ),
            bool_reply(true),
        ]);
        let (mut connection, _) = connect(mock);
        let http = FakePinServer::returning(r#"{"data":"YWJj"}"#);

        pinserver::run_unlock(&mut connection, JadeNetwork::Mainnet, http.as_ref(), 0)
            .await
            .unwrap();

        let calls = http.calls.lock().unwrap();
        assert_eq!(calls[0].0, "https://jadepin.blockstream.com/get_pin");
    }

    // ------------------------------------------------------------------
    // Value conversion
    // ------------------------------------------------------------------

    #[test]
    fn cbor_and_json_round_trip_for_the_shapes_the_pinserver_uses() {
        let cbor = ciborium::Value::Map(vec![
            (text("data"), text("cGF5bG9hZA==")),
            (text("count"), int(3)),
            (text("ok"), ciborium::Value::Bool(true)),
        ]);
        let json = pinserver::cbor_to_json(&cbor).unwrap();
        assert_eq!(json["data"], "cGF5bG9hZA==");
        assert_eq!(json["count"], 3);
        assert_eq!(json["ok"], true);

        // Compare as sets of entries: serde_json sorts object keys while CBOR
        // preserves insertion order, and Jade's docs state that named field
        // order is unimportant.
        let entries = |value: &ciborium::Value| -> Vec<(String, ciborium::Value)> {
            let ciborium::Value::Map(entries) = value else {
                panic!("expected a map");
            };
            let mut entries: Vec<(String, ciborium::Value)> = entries
                .iter()
                .map(|(key, value)| (key.as_text().unwrap().to_string(), value.clone()))
                .collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            entries
        };
        let back = pinserver::json_to_cbor(&json).unwrap();
        assert_eq!(entries(&back), entries(&cbor));
    }

    #[test]
    fn a_byte_string_is_not_silently_rendered_as_json() {
        // The pinserver protocol carries binary as base64 text, so a raw byte
        // string means the device sent something unexpected.
        let cbor = ciborium::Value::Map(vec![(text("data"), ciborium::Value::Bytes(vec![1, 2]))]);
        assert!(pinserver::cbor_to_json(&cbor).is_err());
    }
}

// ============================================================================
// Firmware version comparison
// ============================================================================

mod firmware {
    use crate::types::{version_at_least, MIN_JADE_FIRMWARE_TAPROOT};

    #[test]
    fn versions_compare_by_component_not_lexically() {
        assert!(version_at_least("1.0.34", "1.0.34"));
        assert!(version_at_least("1.0.41", "1.0.34"));
        assert!(version_at_least("1.1.0", "1.0.34"));
        assert!(!version_at_least("1.0.33", "1.0.34"));
        assert!(!version_at_least("0.1.48", "1.0.34"));
        // Lexically "1.0.9" sorts after "1.0.34", numerically it does not.
        assert!(!version_at_least("1.0.9", "1.0.34"));
    }

    #[test]
    fn a_build_suffix_does_not_defeat_the_comparison() {
        assert!(version_at_least("1.0.34-dirty", MIN_JADE_FIRMWARE_TAPROOT));
        assert!(version_at_least("1.0.35+ble", MIN_JADE_FIRMWARE_TAPROOT));
    }

    #[test]
    fn an_unparsable_version_never_blocks_the_operation_by_itself() {
        // The device stays the authority; it rejects what it cannot do.
        assert!(!version_at_least("", "1.0.34"));
        assert!(!version_at_least("nonsense", "1.0.34"));
    }
}

// ============================================================================
// Serial transport
// ============================================================================

#[cfg(feature = "serial")]
mod serial {
    use crate::serial::clears_modem_lines;

    #[test]
    fn modem_lines_are_cleared_only_on_the_tty_node() {
        // Linux, and the macOS dial-in node, assert both lines on open, which
        // reboots the device.
        assert!(clears_modem_lines("/dev/ttyUSB0"));
        assert!(clears_modem_lines("/dev/ttyACM0"));
        assert!(clears_modem_lines("/dev/tty.usbserial-01EDCAEC"));

        // The macOS call-out node needs both left asserted. Clearing them there
        // stops the device answering until it is power cycled, which is the one
        // failure this rule exists to prevent.
        assert!(!clears_modem_lines("/dev/cu.usbserial-01EDCAEC"));
        assert!(!clears_modem_lines("COM3"));
    }
}

// ============================================================================
// Operation deadlines
// ============================================================================

mod deadlines {
    use crate::error::JadeError;
    use crate::transport::{JadeConnection, JadeTransport};
    use async_trait::async_trait;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    /// A transport whose write never completes.
    ///
    /// This is what a Bluetooth write with response does on a degraded link:
    /// the future stays pending because the acknowledgement never arrives.
    struct StalledWrite;

    #[async_trait]
    impl JadeTransport for StalledWrite {
        async fn write_all(&self, _data: Vec<u8>) -> Result<(), JadeError> {
            std::future::pending::<()>().await;
            unreachable!()
        }

        async fn read_some(&self, _timeout: Duration) -> Result<Vec<u8>, JadeError> {
            Ok(Vec::new())
        }

        async fn close(&self) -> Result<(), JadeError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_write_that_never_completes_still_honours_the_deadline() {
        let mut connection =
            JadeConnection::new(Arc::new(StalledWrite), Arc::new(AtomicBool::new(false)));

        let error = connection
            .exchange("ping", Option::<()>::None, Duration::from_millis(100))
            .await
            .unwrap_err();

        // While the write ran unbounded this call never returned at all, so the
        // caller's timeout was silently not a timeout.
        assert!(matches!(error, JadeError::Timeout), "got {error:?}");
    }

    #[tokio::test]
    async fn a_stalled_write_poisons_the_connection() {
        let mut connection =
            JadeConnection::new(Arc::new(StalledWrite), Arc::new(AtomicBool::new(false)));
        let _ = connection
            .exchange("ping", Option::<()>::None, Duration::from_millis(50))
            .await;

        // The device never received a whole request, so the stream cannot be
        // picked back up where it left off.
        let error = connection
            .exchange("ping", Option::<()>::None, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(
            matches!(error, JadeError::DeviceDisconnected),
            "got {error:?}"
        );
    }
}

mod signed_psbt {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip32::{DerivationPath, Fingerprint};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

    use crate::client::{verify_psbt_fingerprint, verify_signed_psbt};
    use crate::JadeError;

    fn previous_transaction(value: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn unsigned() -> Psbt {
        let previous = previous_transaction(10_000);
        let spend = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(previous.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(9_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(spend).expect("unsigned psbt");
        psbt.inputs[0].witness_utxo = Some(previous.output[0].clone());
        psbt.inputs[0].non_witness_utxo = Some(previous);
        psbt
    }

    fn signed_from(sent: &Psbt) -> Psbt {
        let mut signed = sent.clone();
        signed.inputs[0].final_script_witness = Some(Witness::new());
        signed
    }

    #[test]
    fn a_psbt_without_key_origins_is_rejected() {
        let psbt = unsigned();

        let error = verify_psbt_fingerprint(&psbt, "01020304").unwrap_err();

        assert!(matches!(error, JadeError::InvalidPsbt { .. }));
    }

    #[test]
    fn a_psbt_for_another_fingerprint_is_rejected() {
        let mut psbt = unsigned();
        let secret_key = SecretKey::from_slice(&[1; 32]).expect("valid secret key");
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
        psbt.inputs[0].bip32_derivation.insert(
            public_key,
            (Fingerprint::from([1, 2, 3, 4]), DerivationPath::master()),
        );

        let error = verify_psbt_fingerprint(&psbt, "05060708").unwrap_err();

        assert_eq!(
            error,
            JadeError::FingerprintMismatch {
                device: "05060708".to_string(),
                psbt: "01020304".to_string(),
            }
        );
    }

    #[test]
    fn a_psbt_for_the_device_fingerprint_is_accepted() {
        let mut psbt = unsigned();
        let secret_key = SecretKey::from_slice(&[1; 32]).expect("valid secret key");
        let public_key = PublicKey::from_secret_key(&Secp256k1::new(), &secret_key);
        psbt.inputs[0].bip32_derivation.insert(
            public_key,
            (Fingerprint::from([1, 2, 3, 4]), DerivationPath::master()),
        );

        assert_eq!(verify_psbt_fingerprint(&psbt, "01020304"), Ok(()));
    }

    #[test]
    fn a_dropped_previous_transaction_is_accepted() {
        let sent = unsigned();
        let mut signed = signed_from(&sent);
        signed.inputs[0].non_witness_utxo = None;

        assert_eq!(verify_signed_psbt(&sent, &signed), Ok(()));
    }

    #[test]
    fn a_dropped_witness_utxo_is_accepted() {
        let sent = unsigned();
        let mut signed = signed_from(&sent);
        signed.inputs[0].witness_utxo = None;

        assert_eq!(verify_signed_psbt(&sent, &signed), Ok(()));
    }

    #[test]
    fn a_previous_transaction_echoed_without_witness_data_is_accepted() {
        let mut sent = unsigned();
        let mut with_witness = previous_transaction(10_000);
        with_witness.input.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1u8, 2, 3]]),
        });
        sent.inputs[0].non_witness_utxo = Some(with_witness.clone());
        let mut signed = signed_from(&sent);
        let mut stripped = with_witness;
        stripped.input[0].witness = Witness::new();
        signed.inputs[0].non_witness_utxo = Some(stripped);

        assert_eq!(verify_signed_psbt(&sent, &signed), Ok(()));
    }

    #[test]
    fn an_altered_previous_transaction_is_rejected() {
        let sent = unsigned();
        let mut signed = signed_from(&sent);
        signed.inputs[0].non_witness_utxo = Some(previous_transaction(20_000));

        assert!(matches!(
            verify_signed_psbt(&sent, &signed),
            Err(JadeError::InvalidPsbt { .. })
        ));
    }

    #[test]
    fn an_altered_witness_utxo_is_rejected() {
        let sent = unsigned();
        let mut signed = signed_from(&sent);
        signed.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        });

        assert!(matches!(
            verify_signed_psbt(&sent, &signed),
            Err(JadeError::InvalidPsbt { .. })
        ));
    }

    #[test]
    fn a_reply_without_signatures_is_rejected() {
        let sent = unsigned();
        let signed = sent.clone();

        assert_eq!(
            verify_signed_psbt(&sent, &signed),
            Err(JadeError::NothingSigned)
        );
    }
}
