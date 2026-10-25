//! Poltergift in the browser: the same ring-signature code and round model as the native client,
//! compiled to `wasm32-unknown-unknown` with a minimal C ABI so the page needs no bindings
//! generator. JavaScript writes a UTF-8 JSON request into memory obtained from [`pg_alloc`], calls
//! [`pg_call`], reads the reply (a little-endian `u32` length followed by UTF-8 JSON) and releases
//! both buffers with [`pg_free`].

pub mod api;
pub mod demo_output;

/// Allocates `len` bytes for the caller and returns their address.
#[unsafe(no_mangle)]
pub extern "C" fn pg_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// Releases a buffer from [`pg_alloc`] or [`pg_call`]. `len` is the size it was allocated with.
///
/// # Safety
///
/// `ptr` must come from `pg_alloc(len)` or be a `pg_call` reply of total size `len`, and must not be
/// used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pg_free(ptr: *mut u8, len: usize) {
    // SAFETY: the caller guarantees `ptr` came from a `Vec<u8>` with capacity `len.max(1)`.
    drop(unsafe { Vec::from_raw_parts(ptr, 0, len.max(1)) });
}

/// Handles one JSON request (`len` bytes at `ptr`) and returns a reply buffer laid out as
/// `[len: u32 LE][json bytes]`, whose total size is `4 + len`.
///
/// # Safety
///
/// `ptr` must point to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pg_call(ptr: *const u8, len: usize) -> *mut u8 {
    // SAFETY: the caller guarantees `len` readable bytes at `ptr`.
    let input = unsafe { core::slice::from_raw_parts(ptr, len) };
    let reply = match core::str::from_utf8(input) {
        Ok(s) => api::call(s),
        Err(_) => r#"{"ok":false,"error":"request is not UTF-8"}"#.to_string(),
    };
    let body = reply.into_bytes();
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    let mut out = core::mem::ManuallyDrop::new(out);
    out.as_mut_ptr()
}

#[cfg(test)]
mod tests;
