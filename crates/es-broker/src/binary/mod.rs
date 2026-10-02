pub mod client;
pub mod codec;
pub mod pipelined;
pub mod server;

pub use client::{BinaryClient, ClientOptions};
pub use codec::ClientTls;
pub use pipelined::PipelinedClient;
pub use server::serve_binary;
