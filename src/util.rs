use std::future::Future;
use std::thread;
use std::time::Duration;
use anyhow::Result;
use log::warn;
use tokio::time;

pub fn must<F: Fn() -> Result<T>, T>(f: F) -> T {
    loop {
        let res = f();
        match res {
            Ok(data) => return data,
            Err(e) => {
                warn!("{}",e);
                thread::sleep(Duration::from_secs(10))
            }
        }
    }
}


pub async fn async_must<T, E, F>(f: F) -> T
where
    E: Future<Output=Result<T>> + Sized,
    F: Fn() -> E,
{
    loop {
        let res = f().await;
        match res {
            Ok(data) => return data,
            Err(e) => {
                warn!("err: {}", e);
                time::sleep(Duration::from_secs(10)).await
            }
        }
    }
}