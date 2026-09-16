//! Byte transport and the request/reply loop.
//!
//! [`JadeTransport`] is the seam every link goes through. This crate ships a
//! serial implementation; a host application supplies its own for Bluetooth,
//! because BLE permissions and lifecycle belong to the platform rather than
//! here. Tests substitute a scripted double.
//!
//! `JadeConnection` sits above the transport and owns the read buffer, the
//! request id counter and the reply correlation rules.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;

use crate::error::JadeError;
use crate::protocol::{
    classify, decode_reply, encode_request, try_take_frame, JadeReply, ReplyMatch, RequestIds,
    MAX_FRAME_BYTES,
};

/// Bluetooth writes are capped here regardless of the reported MTU.
///
/// A transport implementation should clamp its own chunk size into
/// `1..=MAX_CHUNK_BYTES`: a zero would stall the write loop, and anything above
/// this is rejected by the link layer.
pub const MAX_CHUNK_BYTES: u32 = 509;

/// How long a single `read_chunk` may block.
///
/// Deliberately short. The long per-operation deadline is enforced by the loop
/// in `exchange`, so a user taking two minutes to confirm on the device does not
/// sit inside one uninterruptible native call.
const READ_CHUNK_TIMEOUT_MS: u32 = 250;

/// Floor on the polling interval when a read returns nothing.
///
/// A native implementation that returns immediately with no data would
/// otherwise turn the read loop into a busy spin that pins a blocking thread.
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Maximum number of fragments accepted for one extended reply.
pub(crate) const MAX_REPLY_FRAGMENTS: u32 = 64;

/// Maximum bytes accepted after reassembling an extended reply.
pub(crate) const MAX_REASSEMBLED_BYTES: usize = MAX_FRAME_BYTES;

/// A byte pipe to a device.
///
/// Implementations only move bytes; all framing and protocol handling lives
/// above this trait. Three rules matter for a Bluetooth implementation:
///
/// 1. **Write with response.** Write-without-response silently drops chunks on
///    the ESP32 GATT stack.
/// 2. **Do not pause between chunks of one request.** Firmware discards a
///    partially received message after two seconds of silence, three on Jade
///    v1, and answers with an unattributed error.
/// 3. **`read_some` should return promptly** and honour its timeout. An empty
///    vector means nothing arrived, which is the normal state while the user is
///    deciding on the device.
#[async_trait]
pub trait JadeTransport: Send + Sync {
    /// Write a complete request. Implementations chunk as the transport needs.
    ///
    /// Takes ownership because callback and serial implementations both hand the
    /// buffer to a blocking task, which needs a `'static` payload.
    ///
    /// This may await the link for as long as it needs. The caller's deadline
    /// covers the write as well as the reply, so an implementation that never
    /// completes, which a Bluetooth write with response does whenever the
    /// acknowledgement never arrives, surfaces as [`JadeError::Timeout`] rather
    /// than hanging the operation.
    async fn write_all(&self, data: Vec<u8>) -> Result<(), JadeError>;

    /// Read whatever has arrived, waiting at most `timeout`.
    ///
    /// An empty vector means nothing arrived, which is not an error.
    async fn read_some(&self, timeout: Duration) -> Result<Vec<u8>, JadeError>;

    /// Release the device. Safe to call more than once.
    async fn close(&self) -> Result<(), JadeError>;
}

/// Aborts an operation from outside the task running it.
///
/// Jade has no cancel message, so the only way to stop a pending confirmation
/// is to close the link. A handle can be taken before starting an operation and
/// used while that operation holds `&mut Jade`, which is how a caller
/// implements a cancel button on a signing screen.
#[derive(Clone)]
pub struct CancelHandle {
    aborted: Arc<AtomicBool>,
    transport: Arc<dyn JadeTransport>,
}

impl std::fmt::Debug for CancelHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelHandle")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl CancelHandle {
    /// Signal the abort and close the link.
    ///
    /// The operation in flight fails with `JadeError::UserCancelled`, whether it
    /// notices the flag or the closed link first.
    pub async fn cancel(&self) -> Result<(), JadeError> {
        self.aborted.store(true, Ordering::SeqCst);
        self.transport.close().await
    }

    pub fn is_cancelled(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }
}

/// A request/reply session over one transport.
pub(crate) struct JadeConnection {
    transport: Arc<dyn JadeTransport>,
    buffer: Vec<u8>,
    ids: RequestIds,
    /// Set when the stream can no longer be trusted. A framing failure or a
    /// transport error leaves no way to find the next frame boundary, so the
    /// connection refuses further work rather than returning confusing errors
    /// far from the real cause.
    poisoned: bool,
    aborted: Arc<AtomicBool>,
    min_firmware: String,
}

impl JadeConnection {
    pub(crate) fn new(transport: Arc<dyn JadeTransport>, aborted: Arc<AtomicBool>) -> Self {
        Self {
            transport,
            buffer: Vec::new(),
            ids: RequestIds::new(),
            poisoned: false,
            aborted,
            min_firmware: crate::types::MIN_JADE_FIRMWARE.to_string(),
        }
    }

    pub(crate) fn cancel_handle(&self) -> CancelHandle {
        CancelHandle {
            aborted: Arc::clone(&self.aborted),
            transport: Arc::clone(&self.transport),
        }
    }

    pub(crate) fn transport(&self) -> Arc<dyn JadeTransport> {
        Arc::clone(&self.transport)
    }

    fn check_usable(&self) -> Result<(), JadeError> {
        if self.poisoned {
            return Err(JadeError::DeviceDisconnected);
        }
        if self.aborted.load(Ordering::SeqCst) {
            return Err(JadeError::UserCancelled);
        }
        Ok(())
    }

    /// Report a deliberate abort as a cancellation, whatever the link did.
    ///
    /// `CancelHandle::cancel` sets the flag and closes the transport, so the two
    /// reach this connection by different routes and either can be noticed
    /// first. The loop in `await_reply` reads the flag once per iteration, but a
    /// cancel landing while it is parked inside `read_some`, which is where a
    /// Bluetooth transport spends most of a confirmation because it honours the
    /// read timeout, surfaces only as a transport error: the read returns the
    /// close and the flag is never re-read. Prefer the flag, so a cancel button
    /// always reports `UserCancelled` rather than a disconnection the user did
    /// not experience.
    fn abort_or(&self, error: JadeError) -> JadeError {
        if self.aborted.load(Ordering::SeqCst) {
            JadeError::UserCancelled
        } else {
            error
        }
    }

    /// Mark the stream unusable and drop anything half read.
    fn poison(&mut self) {
        self.poisoned = true;
        self.buffer.clear();
    }

    /// Send a request and wait for its reply.
    pub(crate) async fn exchange<P: Serialize>(
        &mut self,
        method: &str,
        params: Option<P>,
        timeout: Duration,
    ) -> Result<JadeReply, JadeError> {
        self.check_usable()?;

        let id = self.ids.next_id();
        let request = encode_request(&id, method, params)?;
        log::debug!("[jade] -> {method} id={id} ({} bytes)", request.len());

        let remaining = self.write_request(request, timeout).await?;
        self.await_reply(&id, method, remaining).await
    }

    /// Write one request, and return how much of `timeout` is left for the reply.
    ///
    /// The write shares the caller's deadline rather than running unbounded.
    /// `write_all` is free to await the link, and a Bluetooth write with
    /// response does exactly that until the acknowledgement arrives, so a stalled
    /// link would otherwise leave the whole operation pending forever and defeat
    /// the timeout the caller asked for. On a signing call that means a request
    /// that never returns and never fails.
    async fn write_request(
        &mut self,
        request: Vec<u8>,
        timeout: Duration,
    ) -> Result<Duration, JadeError> {
        let deadline = Instant::now() + timeout;
        match tokio::time::timeout(timeout, self.transport.write_all(request)).await {
            Ok(Ok(())) => Ok(deadline.saturating_duration_since(Instant::now())),
            Ok(Err(error)) => {
                self.poison();
                Err(self.abort_or(error))
            }
            Err(_) => {
                self.poison();
                Err(JadeError::Timeout)
            }
        }
    }

    /// Wait for the reply to `id`, discarding log frames and stale replies.
    async fn await_reply(
        &mut self,
        id: &str,
        method: &str,
        timeout: Duration,
    ) -> Result<JadeReply, JadeError> {
        let deadline = Instant::now() + timeout;

        loop {
            // Drain everything already buffered before reading again, so two
            // frames arriving in one read are both seen.
            loop {
                let frame = match try_take_frame(&mut self.buffer) {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(error) => {
                        self.poison();
                        return Err(error);
                    }
                };

                let reply = match decode_reply(&frame) {
                    Ok(reply) => reply,
                    Err(error) => {
                        self.poison();
                        return Err(error);
                    }
                };

                match classify(reply, id) {
                    ReplyMatch::Matched(reply) => {
                        log::debug!("[jade] <- {method} id={id}");
                        return Ok(reply);
                    }
                    ReplyMatch::Unattributed(error) => {
                        // The device rejected the message before it could
                        // recover the id. This is terminal for the request in
                        // flight; ignoring it would strand the caller until the
                        // deadline.
                        log::debug!("[jade] <- {method} unattributed error {}", error.code);
                        return Err(JadeError::from_rpc(
                            error.code,
                            error.message,
                            &self.min_firmware,
                        ));
                    }
                    ReplyMatch::Ignore => continue,
                }
            }

            if self.aborted.load(Ordering::SeqCst) {
                self.poison();
                return Err(JadeError::UserCancelled);
            }
            let now = Instant::now();
            if now >= deadline {
                self.poison();
                return Err(JadeError::Timeout);
            }

            let remaining = deadline - now;
            let slice = remaining.min(Duration::from_millis(u64::from(READ_CHUNK_TIMEOUT_MS)));
            let chunk = match self.transport.read_some(slice).await {
                Ok(chunk) => chunk,
                Err(error) => {
                    self.poison();
                    return Err(self.abort_or(error));
                }
            };

            if chunk.is_empty() {
                // Nothing yet. Yield so a native implementation that returns
                // immediately cannot spin a blocking thread at full tilt.
                tokio::time::sleep(IDLE_POLL_INTERVAL.min(remaining)).await;
            } else {
                self.buffer.extend_from_slice(&chunk);
            }
        }
    }

    /// Send a request whose reply may arrive in `seqnum`/`seqlen` fragments and
    /// return the concatenated bytes.
    ///
    /// Fragments are fetched with `get_extended_data`. Each of those carries its
    /// own fresh request id while `origid` names the original request, so the id
    /// being matched changes on every round. `seqnum` must advance by exactly
    /// one and `seqlen` must be echoed unchanged, or the device aborts with a
    /// protocol error.
    ///
    /// Any failure part way through poisons the connection: the device stays
    /// blocked waiting for the next fragment request, so the link has to be torn
    /// down rather than reused.
    pub(crate) async fn exchange_reassembled<P: Serialize>(
        &mut self,
        method: &str,
        params: Option<P>,
        timeout: Duration,
    ) -> Result<Vec<u8>, JadeError> {
        self.check_usable()?;

        let deadline = Instant::now() + timeout;
        let origid = self.ids.next_id();
        let request = encode_request(&origid, method, params)?;
        log::debug!("[jade] -> {method} id={origid} ({} bytes)", request.len());
        let remaining = remaining_until(deadline)?;
        let remaining = self.write_request(request, remaining).await?;

        let reply = self.await_reply(&origid, method, remaining).await?;
        let seqlen = reply.seqlen.unwrap_or(1);
        let mut seqnum = reply.seqnum.unwrap_or(1);
        let mut payload = crate::protocol::result_bytes(&reply.into_result(&self.min_firmware)?)?;

        if seqnum != 1 || seqlen == 0 || seqlen > MAX_REPLY_FRAGMENTS {
            self.poison();
            return Err(JadeError::protocol(format!(
                "invalid fragment sequence {seqnum} of {seqlen}"
            )));
        }
        if payload.len() > MAX_REASSEMBLED_BYTES {
            self.poison();
            return Err(reply_too_large());
        }

        if seqlen > 1 {
            log::debug!("[jade] {method} reply spans {seqlen} fragments");
        }

        while seqnum < seqlen {
            let next = seqnum + 1;
            let remaining = match remaining_until(deadline) {
                Ok(remaining) => remaining,
                Err(error) => {
                    self.poison();
                    return Err(error);
                }
            };
            let fragment = match self
                .fetch_fragment(&origid, method, next, seqlen, remaining)
                .await
            {
                Ok(fragment) => fragment,
                Err(error) => {
                    // Leaving the device mid-stream desynchronises it; the
                    // connection cannot be reused.
                    self.poisoned = true;
                    return Err(error);
                }
            };
            let combined_len = match payload.len().checked_add(fragment.len()) {
                Some(length) => length,
                None => {
                    self.poison();
                    return Err(reply_too_large());
                }
            };
            if combined_len > MAX_REASSEMBLED_BYTES {
                self.poison();
                return Err(reply_too_large());
            }
            payload.extend_from_slice(&fragment);
            seqnum = next;
        }

        Ok(payload)
    }

    async fn fetch_fragment(
        &mut self,
        origid: &str,
        orig: &str,
        seqnum: u32,
        seqlen: u32,
        timeout: Duration,
    ) -> Result<Vec<u8>, JadeError> {
        #[derive(Serialize)]
        struct ExtendedDataParams<'a> {
            origid: &'a str,
            orig: &'a str,
            seqnum: u32,
            seqlen: u32,
        }

        let params = ExtendedDataParams {
            origid,
            orig,
            seqnum,
            seqlen,
        };
        let reply = self
            .exchange("get_extended_data", Some(params), timeout)
            .await?;

        if reply.seqnum != Some(seqnum) {
            return Err(JadeError::protocol(format!(
                "expected fragment {seqnum}, device sent {:?}",
                reply.seqnum
            )));
        }
        if reply.seqlen != Some(seqlen) {
            return Err(JadeError::protocol(format!(
                "expected {seqlen} fragments, device reported {:?}",
                reply.seqlen
            )));
        }
        crate::protocol::result_bytes(&reply.into_result(&self.min_firmware)?)
    }
}

fn remaining_until(deadline: Instant) -> Result<Duration, JadeError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(JadeError::Timeout);
    }
    Ok(remaining)
}

fn reply_too_large() -> JadeError {
    JadeError::protocol(format!(
        "extended reply exceeded the {MAX_REASSEMBLED_BYTES} byte limit"
    ))
}
