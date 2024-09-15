#![feature(async_closure)]
#![feature(error_in_core)]

mod client;
mod util;

use std::str::FromStr;
use std::time::Duration;
use anyhow::anyhow;
use argh::FromArgs;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Amount, PrivateKey, Transaction, Txid};
use bitcoin::key::UntweakedPublicKey;
use log::{debug, error, info, warn, LevelFilter};
use ord_rs::wallet::{
    CreateCommitTransactionArgsV2, RevealTransactionArgs, SignCommitTransactionArgs, TaprootKeypair,
};
use ord_rs::{Brc20, OrdTransactionBuilder, Utxo};
use tokio::time::sleep;
use client::Network;
use crate::client::{get_cur_tx_fee, get_max_brc20_tx_fee, RpcClient, Timeout, API_KEY, MAX_COMMIT_FEE, MAX_REVEAL_FEE};
use crate::util::async_must;

use clap::{arg, value_parser, Arg, ArgAction, ArgMatches, Command};
use serde::de::Unexpected::Str;

fn cli() -> Command {
    Command::new("inscript")
        .arg(Arg::new("api-key").required(true))
        .arg(Arg::new("private-key").required(true))
        .arg(Arg::new("ticker").required(true))
        .arg(Arg::new("amount").value_parser(value_parser!(u64)).required(true))

        .arg(Arg::new("max-fee").value_parser(value_parser!(usize)).default_value("1000"))
        .arg(Arg::new("num").long("num").value_parser(value_parser!(i32)).default_value("0"))
        .arg(Arg::new("log").long("log").default_value("INFO").env("RUST_LOG"))
        .arg(Arg::new("network").long("network").default_value("mainnet"))
}


#[tokio::main]
async fn main() {
    let mut matches = cli().get_matches();
    match matches.subcommand() {
        None => {
            inscript_command(&mut matches).await.unwrap();
        }

        _ => unreachable!()
    }
}


async fn inscript_command(cmd: &mut ArgMatches) -> anyhow::Result<()> {
    let api_key = cmd.get_one::<String>("api-key").unwrap();
    let private_str = cmd.get_one::<String>("private-key").unwrap();
    let ticker = cmd.get_one::<String>("ticker").unwrap();
    let amount = *cmd.get_one::<u64>("amount").unwrap();
    let count = *cmd.get_one::<i32>("num").unwrap();
    let network_str = cmd.get_one::<String>("network").unwrap();
    let log = cmd.get_one::<String>("log").unwrap();

    let max_fee = *cmd.get_one::<usize>("max-fee").unwrap();

    unsafe { MAX_FEE = max_fee }

    env_logger::builder().filter_level(LevelFilter::from_str(log).unwrap()).try_init().unwrap();

    unsafe { API_KEY.set(api_key.to_string()); }
    let network = Network::from_str(network_str).unwrap();

    let private_key = PrivateKey::from_wif(private_str).unwrap();
    let public_key = private_key.public_key(&Secp256k1::new());
    let sender_address=Address::p2wpkh(&public_key,bitcoin::Network::Bitcoin).unwrap();

   // let public_key = UntweakedPublicKey::from(public_key);
    //let sender_address = Address::p2tr(&Secp256k1::new(), public_key, None, bitcoin::Network::Bitcoin);


    println!("钱包: {}", &sender_address);
    println!("铭文: {}", ticker);
    println!("amount: {}", amount);
    println!("最大gas费: {}", max_fee);
    println!("次数: {}", count);
    println!("网络: {}", network_str);
    println!("日志级别: {}", log);

    // let private_str = "KzG2r2WaPusgRxVCm2imqc2F487mvSkzYEBkSBqh7nQiZyLK514w";
    // let ticker = "helloBTC000";
    // let amount = 10;
    // let network = Network::Testnet;

    let utxos = RpcClient::get_utxo_by_address(sender_address.clone(), network).await?;
    debug!("address: {}, utxos: {:?}", &sender_address, &utxos);
    if utxos.len() == 0 {
        error!("address[{}] need utxos",&sender_address);
        return Err(anyhow::anyhow!("none utxos"));
    }

    let mut best_utxo = utxos.get(0).unwrap().clone();
    for utxo in utxos.iter().skip(1) {
        if utxo.amount > best_utxo.amount {
            best_utxo = utxo.clone()
        }
    }


    println!("best_utxo: {:?}", &best_utxo);


    let utxo = utxos.get(0).unwrap();
    let mut inputs = vec![(best_utxo.id.clone(), best_utxo.index)];

    let end = if count == 0 { i32::MAX } else { count };

    for _ in 0..end {
        let next_input = inscript(network, &inputs, private_str, sender_address.clone(), ticker, amount).await?;
        inputs = vec![next_input];
    }

    Ok(())
}


pub static mut MAX_FEE: usize = 0;

async fn inscript(network: Network, inputs: &Vec<(Txid, u32)>, private_key: &str, addr: Address, ticker: &str, amount: u64) -> anyhow::Result<(Txid, u32)> {
    let mut fee_level = 0;
    let max_fee = unsafe {
        MAX_FEE
    };
    loop {
        let fees = async_must(|| async { get_cur_tx_fee(network).await }).await;
        fee_level += 1;
        let mut fee = match fee_level {
            1 => fees.economy_fee,
            2 => fees.fastest_fee,
            _ => max_fee,
        };

        fee = if fee > max_fee { max_fee } else { fee };

        let (commit_transaction, reveal_transaction) = new_brc20_tx(network, inputs, private_key, addr.clone(), ticker, amount, fee).await;

        let mut i = 0;
        loop {
            let bt_res = RpcClient::broadcast_transaction(&commit_transaction, network).await;
            if bt_res.is_err() {
                i += 1;
                if i > 10 {
                    bt_res?;
                }

                sleep(Duration::from_secs(10)).await;
                continue;
            }

            let tx_id = bt_res.unwrap();
            if tx_id != commit_transaction.txid() {
                return Err(anyhow::anyhow!(
            "unexpected commit_transaction txid: {}, need: {}",tx_id,commit_transaction.txid()
            ));
            }

            break;
        }

        let wait: u64 = if fee == max_fee {
            99999999
        } else {
            600
        };

        let result = RpcClient::wait_for_tx(&commit_transaction.txid(), network, Duration::from_secs(wait)).await;
        if let Err(e) = &result {
            if e.downcast_ref::<Timeout>().is_some() {
                warn!("waited too long. raise fee and try again");
                continue;
            }
        }

        result?;

        let mut i = 0;
        loop {
            let result = RpcClient::broadcast_transaction(&reveal_transaction, network).await;
            if result.is_ok() {
                let tx_id = result.unwrap();
                if tx_id != reveal_transaction.txid() {
                    return Err(anyhow::anyhow!(
            "unexpected reveal_transaction txid: {}, need: {}",tx_id,reveal_transaction.txid()
                ));
                }

                info!("new a brc-20 ticker: {}, txid: {}",ticker,tx_id);
                break;
            }

            i += 1;
            if i > 10 {
                result?;
            }

            sleep(Duration::from_secs(10)).await;
            continue;
        }

        return Ok((commit_transaction.txid(), 1));
    }
}


async fn new_brc20_tx(network: Network, inputs: &Vec<(Txid, u32)>, private_key: &str, addr: Address, ticker: &str, amount: u64, fee: usize) -> (Transaction, Transaction) {
    const script_type: &str = "p2tr";

    let ticker = ticker.to_string();
    let amount = amount;
    let private_key = PrivateKey::from_wif(private_key).unwrap();


    let oneBtc = Amount::from_sat(2500);
    let (mut commit_fee, mut reveal_fee) = (oneBtc, oneBtc);


    let inputs = async_must(|| async { RpcClient::sats_amount_from_tx_inputs(inputs, network).await }).await;

    for i in 0..2 {
        let mut builder = match script_type {
            "p2tr" | "P2TR" => OrdTransactionBuilder::p2tr(private_key),
            "p2wsh" | "P2WSH" => OrdTransactionBuilder::p2wsh(private_key),
            _ => panic!("invalid script type"),
        };

        //创建commit交易
        let commit_tx = builder.build_commit_transaction_with_fixed_fees(
            bitcoin::Network::Bitcoin,
            CreateCommitTransactionArgsV2 {
                inputs: inputs.clone(),
                inscription: Brc20::mint(&ticker, amount),
                txin_script_pubkey: addr.script_pubkey(),
                leftovers_recipient: addr.clone(),
                commit_fee,
                reveal_fee,
                taproot_keypair: Some(TaprootKeypair::Random),
            },
        ).unwrap();

        //commit交易签名
        let signed_commit_tx = builder
            .sign_commit_transaction(
                commit_tx.unsigned_tx,
                SignCommitTransactionArgs {
                    inputs: inputs.clone(),
                    txin_script_pubkey: addr.script_pubkey(),
                    derivation_path: None,
                },
            )
            .await.unwrap();

        let commit_txid = signed_commit_tx.txid();

        //创建reveal交易
        let reveal_transaction = builder
            .build_reveal_transaction(RevealTransactionArgs {
                input: Utxo {
                    id: commit_txid,
                    index: 0,
                    amount: commit_tx.reveal_balance,
                },
                recipient_address: addr.clone(),
                redeem_script: commit_tx.redeem_script,
            })
            .await.unwrap();

        if i == 1 {
            return (signed_commit_tx, reveal_transaction);
        };

        debug!("commit_vsize: {}",signed_commit_tx.vsize());
        debug!("reveal_vsize: {}",reveal_transaction.vsize());

        commit_fee = Amount::from_sat((signed_commit_tx.vsize() * fee) as u64);
        reveal_fee = Amount::from_sat((reveal_transaction.vsize() * fee) as u64);
    }

    unreachable!()
}



