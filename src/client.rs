

use std::collections::HashMap;
use std::fmt::{format, Debug, Display, Formatter};
use std::os::unix::fs::chown;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use bitcoin::{Address, Amount, Transaction, Txid};
use bitcoin::p2p::message::NetworkMessage::Tx;
use bitcoincore_rpc::jsonrpc::minreq::head;
use chrono::TimeDelta;
use clap::builder::Str;
use log::{debug, info};
use ord_rs::wallet::Utxo;
use reqwest::header::HeaderMap;
use reqwest::Url;


pub static mut API_KEY: OnceLock<String> = OnceLock::new();
pub static mut MAX_COMMIT_FEE: u64 = 0;
pub static mut MAX_REVEAL_FEE: u64 = 0;

#[derive(Copy, Clone)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl FromStr for Network {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            _ => Err(anyhow::anyhow!("illegal network {}",s))
        }
    }
}


#[derive(Debug)]
pub struct Timeout;


impl Display for Timeout {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "timeout")
    }
}

impl core::error::Error for Timeout {}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Fees {
    #[serde(alias = "economyFee")]
    pub economy_fee: usize,
    #[serde(alias = "fastestFee")]
    pub fastest_fee: usize,
    #[serde(alias = "minimumFee")]
    pub minimum_fee: usize,
}
pub async fn get_cur_tx_fee(network: Network) -> anyhow::Result<Fees> {
    let resp = if let Network::Mainnet = network {
        let url = r"https://explorer.unisat.io/fractal-mainnet/api/bitcoin-info/fee";
        reqwest::Client::new()
            .get(url)
            .send()
            .await?
    } else {
        let url = r"https://explorer.unisat.io/fractal-testnet/api/bitcoin-info/fee";
        reqwest::Client::new()
            .get(url)
            .send()
            .await?
    };

    if resp.status().is_success() {
        let body = resp.text().await?;
        let result: Result = serde_json::from_str(&body)?;
        Ok(serde_json::from_value(result.data)?)
    } else {
        Err(anyhow::anyhow!(
            "failed to broadcast transaction: {}",
            resp.text().await?
        ))
    }
}

pub struct Brc20Fee {
    pub commit_fee: Amount,
    pub reveal_fee: Amount,
}
pub fn get_max_brc20_tx_fee(network: Network) -> (Brc20Fee) {
    Brc20Fee {
        commit_fee: Amount::from_sat(unsafe { MAX_COMMIT_FEE }),
        reveal_fee: Amount::from_sat(unsafe { MAX_REVEAL_FEE }),
    }
}

pub struct RpcClient;

impl RpcClient {
    // const TESTNET_API_KEY: &'static str = "7e314c5fac4659513bb478964f9146fa8853c8331300cc82ed3e7d4ceedc2288";
    // const MAINNET_API_KEY: &'static str = "260d2ddac3756d53f46685ff86f60bf473197da86eeb28f71bba46220358f652";

    pub fn get_api_key(network: Network) -> String {
        unsafe {
            API_KEY.get().unwrap().to_string()
        }
        // match network {
        //     Network::Mainnet => Self::MAINNET_API_KEY.to_string(),
        //     Network::Testnet => Self::TESTNET_API_KEY.to_string(),
        // }
    }

    const TESTNET_PUSH_TX: &'static str = "https://open-api-fractal-testnet.unisat.io/v1/indexer/local_pushtx";
    const MAINNET_PUSH_TX: &'static str = "https://open-api-fractal.unisat.io/v1/indexer/local_pushtx";
    pub async fn broadcast_transaction(
        transaction: &Transaction,
        network: Network,
    ) -> anyhow::Result<Txid> {
        let url = match network {
            Network::Mainnet => {
                Self::MAINNET_PUSH_TX
            }
            Network::Testnet => {
                Self::TESTNET_PUSH_TX
            }
        };


        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {}", Self::get_api_key(network)).try_into().unwrap());
        headers.insert("Content-Type", "application/json".try_into().unwrap());
        headers.insert("accept", "application/json".try_into().unwrap());

        let tx_hex = hex::encode(bitcoin::consensus::serialize(&transaction));
        let mut json_m = HashMap::new();
        json_m.insert("txHex".to_string(), tx_hex);
        let body = json!(json_m);

        let mut result = reqwest::Client::new()
            .post(url)
            .headers(headers)
            .body(body.to_string())
            .send()
            .await?;

        if result.status().is_success() {
            let body = result.text().await?;
            let result: Result = serde_json::from_str(&body)?;
            Ok(Txid::from_str(result.data.as_str().unwrap())?)
        } else {
            Err(anyhow::anyhow!(
            "failed to broadcast transaction: {}",
            result.text().await?
        ))
        }
    }

    const MAINNET_URL: &'static str = "https://open-api-fractal.unisat.io";
    const TESTNET_URL: &'static str = "https://open-api-fractal-testnet.unisat.io";
    pub async fn get_utxo_by_address(addr: Address, network: Network) -> anyhow::Result<Vec<Utxo>> {
        let url: &'static str = match network {
            Network::Mainnet => {
                Self::MAINNET_URL
            }
            Network::Testnet => {
                Self::TESTNET_URL
            }
        };

        let url = format!("{}/v1/indexer/address/{}/utxo-data", url, addr.to_string());
        let mut url: Url = Url::parse(&url).unwrap();
        url.set_query(Some("cursor=0"));
        url.set_query(Some("size=16"));

        let mut headers = HeaderMap::new();
        headers.insert("Authorization", format!("Bearer {}", Self::get_api_key(network)).try_into().unwrap());
        headers.insert("Content-Type", "application/json".try_into().unwrap());
        headers.insert("accept", "application/json".try_into().unwrap());


        let mut result = reqwest::Client::new()
            .get(url)
            .headers(headers)
            .send()
            .await?;

        #[derive(Deserialize, Serialize, Debug)]
        struct Data {
            pub utxo: Vec<DataUtxo>,
        }
        ;

        #[derive(Deserialize, Serialize, Debug)]
        struct DataUtxo {
            address: String,
            txid: String,
            satoshi: u64,
            vout: u32,
        }

        if result.status().is_success() {
            let body = result.text().await?;
            let result: Result = serde_json::from_str(&body)?;
            let data: Data = serde_json::from_value(result.data)?;

            let mut utxos = Vec::new();
            for utxo in data.utxo {
                utxos.push(Utxo {
                    id: Txid::from_str(&utxo.txid)?,
                    index: utxo.vout,
                    amount: Amount::from_sat(utxo.satoshi),
                })
            }

            Ok(utxos)
        } else {
            Err(anyhow::anyhow!(
            "failed to broadcast transaction: {}",
            result.text().await?
        ))
        }
    }


    pub async fn get_tx_by_hash(txid: &Txid, network: Network) -> anyhow::Result<ApiTransaction> {
        let url = match network {
            Network::Mainnet => {
                format!("https://mempool.fractalbitcoin.io/api/tx/{}", txid)
            }
            Network::Testnet => {
                format!("https://mempool-testnet.fractalbitcoin.io/api/tx/{}", txid)
            }
        };

        let tx = reqwest::get(&url).await?.json().await?;
        Ok(tx)
    }

    pub async fn wait_for_tx(txid: &Txid, network: Network, timeout: Duration) -> anyhow::Result<()> {
        let start = chrono::Local::now();
        let delta = TimeDelta::from_std(timeout).unwrap();

        info!("waiting for transaction to be confirmed. txid: {}",txid);


        loop {
            let tx_res = Self::get_tx_by_hash(txid, network).await;
            if tx_res.is_ok() {
                if tx_res.unwrap().status.confirmed == true {
                    break;
                }
            }

            if chrono::Local::now() - start > delta {
                Err(Timeout)?
            }


            tokio::time::sleep(Duration::from_secs(30)).await;
            debug!("retrying in 30 seconds...");
        }

        Ok(())
    }


    pub async fn sats_amount_from_tx_inputs(
        inputs: &[(Txid, u32)],
        network: Network,
    ) -> anyhow::Result<Vec<Utxo>> {
        let mut output_inputs = Vec::with_capacity(inputs.len());
        for (txid, index) in inputs {
            let tx = Self::get_tx_by_hash(txid, network).await?;
            let output = tx
                .vout
                .get(*index as usize)
                .ok_or_else(|| anyhow::anyhow!("invalid index {} for txid {}", index, txid))?;

            output_inputs.push(Utxo {
                id: *txid,
                index: *index,
                amount: Amount::from_sat(output.value),
            });
        }
        Ok(output_inputs)
    }
}


#[derive(Debug, Deserialize, Serialize)]
struct Result {
    code: isize,
    msg: String,
    data: Value,
}

#[derive(Debug, serde::Deserialize, Serialize)]
pub struct ApiTransaction {
    txid: String,
    vout: Vec<ApiVout>,
    status: TXStatus,
    vsize: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TXStatus {
    confirmed: bool,
    block_height: u64,
    block_hash: String,
    block_time: u64,
}

#[derive(Debug, serde::Deserialize, Serialize)]
pub struct ApiVout {
    value: u64,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use bitcoin::Address;
    use crate::client::{get_cur_tx_fee, Network, RpcClient};
    use crate::client::Network::{Mainnet, Testnet};

    #[test]
    fn get_cur_tx_fee_test() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            get_cur_tx_fee(Testnet).await
        });

        assert!(result.is_ok());
        let result = rt.block_on(async {
            get_cur_tx_fee(Mainnet).await
        });

        assert!(result.is_ok());
    }

    #[test]
    fn get_utxo_by_address_test() {
        let mut rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let addr = Address::from_str("bc1q8fywdq9ukeuu6zzhh7msjt08jvfr9m9vs2y87e").unwrap();
            RpcClient::get_utxo_by_address(addr.assume_checked(), Network::Testnet).await
        });

        assert!(result.is_ok());
        println!("{:?}", result.unwrap());
    }
}