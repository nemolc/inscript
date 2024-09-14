#![feature(async_closure)]
mod client;
pub mod init;
mod util;

use std::str::FromStr;
use std::time::Duration;
use anyhow::anyhow;
use argh::FromArgs;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, Amount, PrivateKey, Transaction, Txid};
use log::{debug, error, info, LevelFilter};
use ord_rs::wallet::{
    CreateCommitTransactionArgsV2, RevealTransactionArgs, SignCommitTransactionArgs, TaprootKeypair,
};
use ord_rs::{Brc20, OrdTransactionBuilder, Utxo};
use tokio::time::sleep;
use client::Network;
use crate::client::{get_cur_tx_fee, get_max_brc20_tx_fee, RpcClient};
use crate::util::async_must;

use clap::{arg, value_parser, Arg, ArgAction, ArgMatches, Command};
use serde::de::Unexpected::Str;
use crate::init::API_KEY;

fn cli() -> Command {
    Command::new("inscript")
        .arg(Arg::new("api-key").required(true))
        .arg(Arg::new("private-key").required(true))
        .arg(Arg::new("ticker").required(true))
        .arg(Arg::new("amount").value_parser(value_parser!(u64)).required(true))
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

    env_logger::builder().filter_level(LevelFilter::from_str(log).unwrap()).try_init().unwrap();

    unsafe { API_KEY.set(api_key.to_string()); }
    let network = Network::from_str(network_str).unwrap();

    let private_key = PrivateKey::from_wif(private_str).unwrap();
    let public_key = private_key.public_key(&Secp256k1::new());
    let sender_address = Address::p2wpkh(&public_key, bitcoin::Network::Bitcoin).unwrap();


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


    println!("wallet: {}", &sender_address);
    println!("ticker: {}", ticker);
    println!("amount: {}", amount);
    println!("num: {}", count);
    println!("best_utxo: {:?}", &best_utxo);
    println!("network: {}", network_str);
    println!("log_level: {}", log);

    let utxo = utxos.get(0).unwrap();
    let mut inputs = vec![(best_utxo.id.clone(), best_utxo.index)];

    let end = if count == 0 { 0 } else { count };

    for _ in 0..end {
        let next_input = inscript(network, &inputs, private_str, ticker, amount).await?;
        inputs = vec![next_input];
    }

    Ok(())
}


async fn inscript(network: Network, inputs: &Vec<(Txid, u32)>, private_key: &str, ticker: &str, amount: u64) -> anyhow::Result<(Txid, u32)> {
    let (commit_transaction, reveal_transaction) = new_brc20_tx(network, inputs, private_key, ticker, amount).await;

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

    RpcClient::wait_for_tx(&commit_transaction.txid(), network, Duration::from_secs(10)).await?;

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

    Ok((commit_transaction.txid(), 1))
}


async fn new_brc20_tx(network: Network, inputs: &Vec<(Txid, u32)>, private_key: &str, ticker: &str, amount: u64) -> (Transaction, Transaction) {
    const script_type: &str = "p2tr";

    let ticker = ticker.to_string();
    let amount = amount;
    let private_key = PrivateKey::from_wif(private_key).unwrap();
    let public_key = private_key.public_key(&Secp256k1::new());
    let sender_address = Address::p2wpkh(&public_key, bitcoin::Network::Bitcoin).unwrap();


    let max_fee = get_max_brc20_tx_fee(network);
    let (mut commit_fee, mut reveal_fee) = (max_fee.commit_fee, max_fee.reveal_fee);

    let fees = async_must(|| async { get_cur_tx_fee(network).await }).await;
    let base_fee = fees.economy_fee;
    let inputs = async_must(|| async { RpcClient::sats_amount_from_tx_inputs(inputs, network).await }).await;

    let mut i = 0;
    loop {
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
                txin_script_pubkey: sender_address.script_pubkey(),
                leftovers_recipient: sender_address.clone(),
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
                    txin_script_pubkey: sender_address.script_pubkey(),
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
                recipient_address: sender_address.clone(),
                redeem_script: commit_tx.redeem_script,
            })
            .await.unwrap();

        if i == 1 {
            return (signed_commit_tx, reveal_transaction);
        };

        let good_commit_fee = signed_commit_tx.vsize() * base_fee;
        if good_commit_fee < commit_fee.to_sat() as usize {
            commit_fee = Amount::from_sat(good_commit_fee as u64);
        }

        let good_reveal_fee = reveal_transaction.vsize() * base_fee;
        if good_reveal_fee < reveal_fee.to_sat() as usize {
            reveal_fee = Amount::from_sat(good_reveal_fee as u64);
        }

        i += 1;
    }
}



