use std::sync::Arc;

extern crate bigint;
extern crate ekiden_common;
extern crate ekiden_epochtime;
extern crate ekiden_ethereum;
extern crate ekiden_stake_base;
#[macro_use(defer)]
extern crate scopeguard;
extern crate grpcio;
extern crate web3;
#[macro_use]
extern crate log;
extern crate itertools;

use ekiden_common::bytes::{B256, H160};
use ekiden_common::entity::Entity;
use ekiden_common::environment::{Environment, GrpcEnvironment};
use ekiden_common::futures::prelude::*;
use ekiden_common::testing;
use ekiden_common::uint::U256;
use ekiden_ethereum::truffle::{deploy_truffle, get_development_address, mine, start_truffle,
                               DEVELOPMENT_ADDRESS};
use ekiden_ethereum::EthereumStake;
use ekiden_stake_base::{AmountType, StakeEscrowBackend};
use itertools::Itertools;
use web3::api::Web3;
use web3::transports::WebSocket;

#[test]
fn stake_integration() {
    testing::try_init_logging();

    let grpc_environment = grpcio::EnvBuilder::new().build();
    let environment = Arc::new(GrpcEnvironment::new(grpc_environment));

    // Spin up truffle.
    let mut truffle = start_truffle(env!("CARGO_MANIFEST_DIR"));
    defer! {{
        drop(truffle.kill());
    }};

    // Connect to truffle.
    let (handle, transport) =
        WebSocket::new("ws://localhost:9545").expect("WebSocket creation should work");
    let client = Web3::new(transport.clone());

    // Make sure our contracts are deployed.
    let addresses = deploy_truffle(env!("CARGO_MANIFEST_DIR"));
    let address = addresses
        .get("Stake")
        .expect("could not find contract address");

    // Run a driver to make some background transactions such that things confirm.
    environment.spawn(mine(transport).discard());

    let eth_address = H160::from_slice(DEVELOPMENT_ADDRESS);
    let oasis = B256::from_slice(&eth_address.to_vec());

    let stake = EthereumStake::new(
        Arc::new(client),
        Arc::new(Entity {
            id: B256::zero(),
            eth_address: Some(eth_address),
        }),
        H160::from_slice(&address),
    ).unwrap();

    let name = stake.get_name().wait().expect("name should work");
    debug!("name = {}", name);
    assert_eq!(name, "EkidenStake"); // see ../migration/2_deploy_contracts.js

    let symbol = stake.get_symbol().wait().expect("symbol should work");
    debug!("symbol = {}", symbol);
    assert_eq!(symbol, "E$");

    let decimals = stake.get_decimals().wait().expect("decimals should work");
    debug!("decimals = {}", decimals);
    assert_eq!(decimals, 18u8);

    let total_supply = stake
        .get_total_supply()
        .wait()
        .expect("totalSupply should work");
    debug!("total_supply = {}", total_supply);
    let scale = U256::from(bigint::uint::U256::exp10(decimals as usize));
    let expected_supply = U256::from(1_000_000_000) * scale;
    assert_eq!(total_supply, expected_supply, "initial supply wrong");

    let stake_status = stake
        .get_stake_status(oasis)
        .wait()
        .expect("getStakeStatus should work");
    debug!("total_stake = {}", stake_status.total_stake);
    debug!("escrowed = {}", stake_status.escrowed);
    assert_eq!(
        stake_status.total_stake, total_supply,
        "initial total_stake should be total supply"
    );
    assert_eq!(
        stake_status.escrowed,
        AmountType::from(0),
        "initial amount escrowed should be zero"
    );

    let oasis_addr = get_development_address(0).expect("should have gotten address 0");
    debug!("oasis_addr          = {:02x}", oasis_addr.iter().format(""));
    debug!(
        "DEVELOPMENT_ADDRESS = {:02x}",
        DEVELOPMENT_ADDRESS.iter().format("")
    );
    assert_eq!(
        oasis_addr, DEVELOPMENT_ADDRESS,
        "truffle framework test data bad?"
    );

    let alice_addr = get_development_address(1).expect("should have gotten address 1");
    debug!("alice_addr          = {:02x}", alice_addr.iter().format(""));
    let alice = B256::from_slice(&alice_addr);
    let bob_addr = get_development_address(2).expect("should have gotten address 2");
    debug!("bob_addr          = {:02x}", bob_addr.iter().format(""));
    let bob = B256::from_slice(&bob_addr);
    let carol_addr = get_development_address(3).expect("should have gotten address 3");
    debug!("carol_addr          = {:02x}", carol_addr.iter().format(""));
    let carol = B256::from_slice(&carol_addr);

    let oasis_balance = stake
        .balance_of(oasis)
        .wait()
        .expect("balanceOf should go through");
    debug!("oasis balance = {}", oasis_balance);
    assert_eq!(oasis_balance, total_supply);

    let alice_balance = stake
        .balance_of(alice)
        .wait()
        .expect("balanceOf should go through");
    debug!("alice balance = {}", alice_balance);
    assert_eq!(alice_balance, AmountType::from(0));

    let oasis_to_alice_transfer_amt = AmountType::from(1000);

    let b = stake
        .transfer(oasis, alice, oasis_to_alice_transfer_amt)
        .wait()
        .expect("transfer from Oasis to Alice should work");
    debug!("transfer to alice: {}", b);
    assert!(b);

    let alice_balance = stake
        .balance_of(alice)
        .wait()
        .expect("balanceOf(alice) should work");
    assert_eq!(
        alice_balance, oasis_to_alice_transfer_amt,
        "post-transfer Alice balance wrong"
    );

    let oasis_balance = stake
        .balance_of(oasis)
        .wait()
        .expect("balanceOf(oasis) should work");
    assert_eq!(
        oasis_balance,
        total_supply - oasis_to_alice_transfer_amt,
        "post-transfer Oasis balance wrong"
    );

    let alice_approval = AmountType::from(100);
    let b = stake
        .approve(oasis, alice, alice_approval)
        .wait()
        .expect("approval should go through");
    assert!(b, "approve should have returned true");

    let oasis_to_bob_transfer_amt = AmountType::from(10);
    let b = stake
        .transfer_from(alice, oasis, bob, oasis_to_bob_transfer_amt)
        .wait()
        .expect("transfer_from oasis to bob should work");
    assert!(b, "approved transfer should return true");

    let bob_balance = stake
        .balance_of(bob)
        .wait()
        .expect("balanceOf(bob) should work");
    assert_eq!(bob_balance, oasis_to_bob_transfer_amt);

    let expected_oasis_balance = oasis_balance - oasis_to_bob_transfer_amt;
    let oasis_balance = stake
        .balance_of(oasis)
        .wait()
        .expect("balanceOf(oasis) should work");
    assert_eq!(
        oasis_balance, expected_oasis_balance,
        "post-approved-transfer oasis balance wrong"
    );

    let expected_remaining_allowance = alice_approval - oasis_to_bob_transfer_amt;
    let remaining_allowance = stake
        .allowance(oasis, alice)
        .wait()
        .expect("allowance(oasis, alice) should work");
    assert_eq!(
        remaining_allowance, expected_remaining_allowance,
        "post-approved-transfer allowance wrong"
    );

    let excessive_transfer_amount = remaining_allowance + AmountType::from(1);
    match stake
        .transfer_from(alice, oasis, bob, excessive_transfer_amount)
        .wait()
    {
        Ok(b) => {
            assert!(
                !b,
                "excessive transfer_from did not revert, and returned TRUE"
            );
        }
        Err(e) => {
            debug!(
                "excessive transfer_from aborted correctly: {}",
                e.description()
            );
        }
    }

    let burn_quantity = AmountType::from(10_000);
    let b = stake
        .burn(oasis, burn_quantity)
        .wait()
        .expect("burn(oasis, 10_000) should work");
    assert!(b, "burn(oasis, 10_000) should succeed and return true");

    let expected_oasis_balance = oasis_balance - burn_quantity;
    let oasis_balance = stake
        .balance_of(oasis)
        .wait()
        .expect("balanceOf(oasis) should continue to work");
    assert_eq!(
        oasis_balance, expected_oasis_balance,
        "post-burn oasis balance wrong"
    );

    let expected_total_supply = total_supply - burn_quantity;
    let total_supply = stake
        .get_total_supply()
        .wait()
        .expect("total_supply after burn should work");
    assert_eq!(total_supply, expected_total_supply);

    let carol_burn_approve_amount = AmountType::from(total_supply) + AmountType::from(10);
    let b = stake
        .approve(oasis, carol, carol_burn_approve_amount)
        .wait()
        .expect("carol burn approval should work");
    assert!(
        b,
        "carol approval should return true, even when exceeds total supply"
    );

    let carol_balance = stake
        .balance_of(carol)
        .wait()
        .expect("balanceOf(carol) should work");
    assert_eq!(carol_balance, AmountType::from(0));

    let carol_burns_oasis_amount = AmountType::from(20_000);
    let b = stake
        .burn_from(carol, oasis, carol_burns_oasis_amount)
        .wait()
        .expect("burn_from should work");
    assert!(b, "burn_from(carol, oasis, 20_000) should return true");

    let expected_oasis_balance = oasis_balance - carol_burns_oasis_amount;
    let oasis_balance = stake.balance_of(oasis).wait().unwrap();
    assert_eq!(
        oasis_balance, expected_oasis_balance,
        "post-burn_from oasis balance wrong"
    );

    let expected_total_supply = total_supply - carol_burns_oasis_amount;
    let total_supply = stake
        .get_total_supply()
        .wait()
        .expect("total_supply after burn_from should work");
    assert_eq!(total_supply, expected_total_supply);

    let alice_to_bob_escrow_amount = AmountType::from(17);
    let alice_to_bob_aux = B256::from_slice(&[4u8; 32]);
    let alice_to_carol_escrow_amount = AmountType::from(23);
    let alice_to_carol_aux = B256::from_slice(&[5u8; 32]);

    debug!("alice account balance = {}", alice_balance);
    let alice_to_bob_escrow_id = stake
        .allocate_escrow(alice, bob, alice_to_bob_escrow_amount, alice_to_bob_aux)
        .wait()
        .expect("allocate_escrow(alice, bob, ...) should work");
    let alice_to_carol_escrow_id = stake
        .allocate_escrow(
            alice,
            carol,
            alice_to_carol_escrow_amount,
            alice_to_carol_aux,
        )
        .wait()
        .expect("allocate_escrow(alice, carol, ...) should work");

    debug!("alice->bob escrow: {}", alice_to_bob_escrow_id);
    debug!("alice->carol escrow: {}", alice_to_carol_escrow_id);

    let alice_bob_status = stake
        .fetch_escrow_by_id(alice_to_bob_escrow_id)
        .wait()
        .expect("fetch_escrow_by_id should work");
    debug!("id {}", alice_bob_status.id);
    debug!("target {}", alice_bob_status.target);
    debug!("amount {}", alice_bob_status.amount);
    debug!("aux {}", alice_bob_status.aux);
    assert_eq!(alice_bob_status.id, alice_to_bob_escrow_id);
    assert_eq!(alice_bob_status.target, bob);
    assert_eq!(alice_bob_status.amount, alice_to_bob_escrow_amount);
    assert_eq!(alice_bob_status.aux, alice_to_bob_aux);

    let it = stake
        .list_active_escrows_iterator(alice)
        .wait()
        .expect("list_active_escrows_iterator(alice) should work");
    debug!("it.has_next {}", it.has_next);
    debug!("it.owner {}", it.owner);
    debug!("it.state {}", it.state);

    let alice_bob_escrow_take = AmountType::from(7);
    let taken = stake.take_and_release_escrow(bob, alice_to_bob_escrow_id, alice_bob_escrow_take).wait()
        .expect("take_and_release_escrow should work");
    assert_eq!(taken, alice_bob_escrow_take);
    let expected_bob_balance = bob_balance + alice_bob_escrow_take;
    let bob_balance = stake
        .balance_of(bob)
        .wait()
        .expect("balanceOf(bob) should work");
    assert_eq!(bob_balance, expected_bob_balance, "post-take Bob balance wrong");
    let expected_alice_balance = alice_balance - alice_to_carol_escrow_amount - taken;
    let alice_balance = stake
        .balance_of(alice)
        .wait()
        .expect("balanceOf(alice) should work");
    assert_eq!(
        alice_balance, expected_alice_balance,
        "post-take Alice balance wrong"
    );

    drop(handle);
}
