use bitcoincore_rpc::{Auth, Client, Error, Result, RpcApi};

fn main() {
a()
}


fn a() {
    let client = Client::new("http://43.154.62.233:8332", Auth::UserPass("dd".to_string(), "20201224.".to_string())).unwrap();
    let info=client.wait_for_new_block(0).unwrap();

    let block_hash = client.get_block_stats(info.height).unwrap();

    println!("{block_hash:?}")
}