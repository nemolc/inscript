use std::sync::OnceLock;

pub static mut API_KEY: OnceLock<String> = OnceLock::new();
