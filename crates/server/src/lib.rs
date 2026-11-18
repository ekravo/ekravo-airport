//! Ekravo Airport server.
//!
//! Layering:
//! - [`config`] validates the environment.
//! - [`db`] and [`store`] own SQLite.
//! - [`auth`] owns passwords, opaque secrets, and access tokens.
//! - [`routes`] exposes the HTTP API and the WebSocket relay.
//! - [`registry`] is the in-memory index of live sockets.

pub mod auth;
pub mod config;
pub mod db;
pub mod error;
pub mod extract;
pub mod ratelimit;
pub mod registry;
pub mod routes;
pub mod state;
pub mod store;
pub mod util;
