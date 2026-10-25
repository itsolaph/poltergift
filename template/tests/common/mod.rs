//! Test harness: drives the real template through the official engine (TemplateTest) and signs
//! with the real client cryptography (`poltergift-ring`).

#![allow(dead_code)]

use poltergift_ring::{self as ring, Purpose, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tari_template_test_tooling::engine_types::virtual_substate::{VirtualSubstate, VirtualSubstateId};
use tari_template_test_tooling::{
    TemplateTest,
    byte_type::ToByteType,
    crypto::{PublicKey as _, RistrettoPublicKey, RistrettoSecretKey},
    engine_types::commit_result::{ExecuteResult, RejectReason},
    support::{assert_error::assert_reject_reason, stealth},
    template_lib_types::{
        Amount, ComponentAddress, NonFungibleAddress, TemplateAddress, constants::TARI_TOKEN,
        crypto::RistrettoPublicKeyBytes, stealth::StealthTransferStatement,
    },
    transaction::{Transaction, args},
};

pub const GIFT: u64 = 5_000_000;
pub const FEE: u64 = 20_000;
pub const PAYOUT: u64 = GIFT - FEE;
pub const JOIN_DEADLINE: u64 = 10;
pub const CLAIM_DEADLINE: u64 = 20;

pub struct Harness {
    pub test: TemplateTest,
    pub template: TemplateAddress,
    pub account: ComponentAddress,
    pub owner_proof: NonFungibleAddress,
    pub account_key: RistrettoSecretKey,
    pub rng: ChaCha20Rng,
    /// When set, account-funded transactions carry a fee instruction paying this much at most.
    pub account_fee: Option<u64>,
}

/// A round as its members see it.
pub struct Round {
    pub component: ComponentAddress,
    pub round_id: [u8; 32],
    pub members: Vec<SecretKey>,
}

impl Round {
    pub fn ring(&self) -> Vec<[u8; 32]> {
        self.members.iter().map(SecretKey::public_key).collect()
    }
}

pub fn pk_bytes(p: [u8; 32]) -> RistrettoPublicKeyBytes {
    RistrettoPublicKeyBytes::from(p)
}

/// A fresh payout statement: no inputs, `amount` revealed in, one stealth output of `amount`.
pub fn payout(amount: u64) -> StealthTransferStatement {
    stealth::generate_transfer_data(stealth::NO_INPUTS, amount, [amount], 0u64).statement
}

pub fn payout_message(statement: &StealthTransferStatement) -> [u8; 32] {
    ring::payout_message(&tari_bor::encode(statement).unwrap())
}

impl Harness {
    pub fn new() -> Self {
        Self::with_templates(&["."])
    }

    /// A harness that also compiles the given extra test templates (paths relative to the crate).
    pub fn with_templates(paths: &[&str]) -> Self {
        let mut test = TemplateTest::new(env!("CARGO_MANIFEST_DIR"), paths.iter().copied());
        let template = test.get_template_address("Round");
        let (account, owner_proof, account_key) = test.create_funded_account();
        let mut h = Self {
            test,
            template,
            account,
            owner_proof,
            account_key,
            rng: ChaCha20Rng::seed_from_u64(0x9057),
            account_fee: None,
        };
        h.set_epoch(1);
        h
    }

    /// A transaction builder for account-funded calls (fee instruction added when fees are on).
    pub fn account_tx(&self) -> tari_template_test_tooling::transaction::TransactionBuilder {
        let b = self.test.transaction();
        match self.account_fee {
            Some(fee) => b.pay_fee_from_component(self.account, fee),
            None => b,
        }
    }

    pub fn set_epoch(&mut self, epoch: u64) {
        self.test.set_virtual_substate(VirtualSubstateId::CurrentEpoch, VirtualSubstate::CurrentEpoch(epoch));
    }

    pub fn new_member(&mut self) -> SecretKey {
        SecretKey::random(&mut self.rng)
    }

    pub fn try_create(
        &mut self,
        gift: u64,
        size: u32,
        join_deadline: u64,
        claim_deadline: u64,
        fee: u64,
    ) -> Result<ComponentAddress, RejectReason> {
        let tx = self
            .account_tx()
            .call_function(
                self.template,
                "create",
                args![Amount::from(gift), size, join_deadline, claim_deadline, Amount::from(fee)],
            )
            .build_and_seal(&self.account_key);
        let result = self.test.execute_and_commit_on_success(tx, vec![]);
        match result.finalize.any_reject() {
            Some(reason) => Err(reason.clone()),
            None => {
                let diff = result.finalize.any_accept().unwrap();
                let component = diff
                    .up_iter()
                    .find_map(|(id, s)| {
                        let c = s.substate_value().component()?;
                        (*c.template_address() == self.template).then(|| id.as_component_address())?
                    })
                    .expect("round component in diff");
                Ok(component)
            }
        }
    }

    /// Creates a round with the default parameters and no members yet.
    pub fn create_round(&mut self, size: u32) -> Round {
        let component = self.try_create(GIFT, size, JOIN_DEADLINE, CLAIM_DEADLINE, FEE).expect("create");
        Round { component, round_id: component.as_object_key().into_array(), members: Vec::new() }
    }

    /// Joins with `gift_amount` withdrawn from the funded account, an arbitrary member key and PoP.
    pub fn try_join_raw(
        &mut self,
        component: ComponentAddress,
        member: [u8; 32],
        pop: Vec<u8>,
        gift_amount: u64,
    ) -> Result<ExecuteResult, RejectReason> {
        let tx = self
            .account_tx()
            .call_method(self.account, "withdraw", args![TARI_TOKEN, Amount::from(gift_amount)])
            .put_last_instruction_output_on_workspace("gift")
            .call_method(component, "join", args![pk_bytes(member), pop, Workspace("gift")])
            .build_and_seal(&self.account_key);
        self.execute(tx, vec![self.owner_proof.clone()])
    }

    pub fn try_join(&mut self, round: &Round, member: &SecretKey) -> Result<ExecuteResult, RejectReason> {
        let pop = ring::sign_pop(&round.round_id, member, &mut self.rng).to_vec();
        self.try_join_raw(round.component, member.public_key(), pop, GIFT)
    }

    /// Creates a round of `size` and fills it with fresh members (sealing it).
    pub fn full_round(&mut self, size: u32) -> Round {
        let mut round = self.create_round(size);
        for _ in 0..size {
            let m = self.new_member();
            self.try_join(&round, &m).expect("join");
            round.members.push(m);
        }
        round
    }

    pub fn execute(&mut self, tx: Transaction, proofs: Vec<NonFungibleAddress>) -> Result<ExecuteResult, RejectReason> {
        let result = self.test.execute_and_commit_on_success(tx, proofs);
        match result.finalize.any_reject() {
            Some(reason) => Err(reason.clone()),
            None => Ok(result),
        }
    }

    /// A throwaway signer for claim and refund transactions: no account, no member key.
    pub fn ephemeral_key(&mut self) -> RistrettoSecretKey {
        <RistrettoSecretKey as tari_template_test_tooling::crypto::SecretKey>::random(&mut self.rng)
    }

    /// Submits a claim the way the client does: in the fee intent, sealed by a throwaway key.
    pub fn submit_claim(
        &mut self,
        component: ComponentAddress,
        key_image: [u8; 32],
        signature: Vec<u8>,
        statement: StealthTransferStatement,
    ) -> Result<ExecuteResult, RejectReason> {
        let key = self.ephemeral_key();
        let tx = self
            .test
            .transaction()
            .with_fee_instructions_builder(|b| {
                b.call_method(component, "claim", args![pk_bytes(key_image), signature, statement])
            })
            .build_and_seal(&key);
        self.execute(tx, vec![])
    }

    pub fn submit_refund(
        &mut self,
        component: ComponentAddress,
        member: [u8; 32],
        key_image: [u8; 32],
        proof: Vec<u8>,
        statement: StealthTransferStatement,
    ) -> Result<ExecuteResult, RejectReason> {
        let key = self.ephemeral_key();
        let tx = self
            .test
            .transaction()
            .with_fee_instructions_builder(|b| {
                b.call_method(component, "refund", args![pk_bytes(member), pk_bytes(key_image), proof, statement])
            })
            .build_and_seal(&key);
        self.execute(tx, vec![])
    }

    /// Member `index` signs a claim for `statement`.
    pub fn sign_claim(
        &mut self,
        round: &Round,
        index: usize,
        statement: &StealthTransferStatement,
    ) -> ([u8; 32], Vec<u8>) {
        let msg = payout_message(statement);
        let (sig, image) = ring::sign(
            Purpose::Claim,
            &round.round_id,
            &round.ring(),
            index,
            &round.members[index],
            &msg,
            &mut self.rng,
        )
        .unwrap();
        (image, sig.to_bytes())
    }

    pub fn claim(&mut self, round: &Round, index: usize) -> Result<ExecuteResult, RejectReason> {
        let statement = payout(PAYOUT);
        let (image, sig) = self.sign_claim(round, index, &statement);
        self.submit_claim(round.component, image, sig, statement)
    }

    pub fn sign_refund(
        &mut self,
        round: &Round,
        index: usize,
        statement: &StealthTransferStatement,
    ) -> ([u8; 32], Vec<u8>) {
        let msg = payout_message(statement);
        let member = &round.members[index];
        let (sig, image) =
            ring::sign(Purpose::Refund, &round.round_id, &[member.public_key()], 0, member, &msg, &mut self.rng)
                .unwrap();
        (image, sig.to_bytes())
    }

    pub fn refund(&mut self, round: &Round, index: usize) -> Result<ExecuteResult, RejectReason> {
        let statement = payout(PAYOUT);
        let (image, proof) = self.sign_refund(round, index, &statement);
        self.submit_refund(round.component, round.members[index].public_key(), image, proof, statement)
    }

    /// `(joined, size, claims, refunds, sealed)`
    pub fn status(&mut self, component: ComponentAddress) -> (u32, u32, u32, u32, bool) {
        self.view(component, "status")
    }

    pub fn vault_balance(&mut self, component: ComponentAddress) -> u64 {
        let amount: Amount = self.view(component, "balance");
        u64::try_from(amount.to_u128()).unwrap()
    }

    /// Calls a read-only method. Views are free in tests, so fees are paused around the call.
    fn view<T: serde::de::DeserializeOwned + for<'b> tari_bor::Decode<'b, ()>>(
        &mut self,
        component: ComponentAddress,
        method: &str,
    ) -> T {
        if self.account_fee.is_some() {
            self.test.disable_fees();
        }
        let value = self.test.call_method(component, method, args![], vec![]);
        if self.account_fee.is_some() {
            self.test.enable_fees();
        }
        value
    }
}

#[track_caller]
pub fn expect_reject(result: Result<ExecuteResult, RejectReason>, reason: &str) {
    match result {
        Ok(_) => panic!("expected rejection containing {reason:?}, but the transaction succeeded"),
        Err(r) => assert_reject_reason(r, reason),
    }
}

pub fn public_key_of(sk: &RistrettoSecretKey) -> RistrettoPublicKeyBytes {
    RistrettoPublicKey::from_secret_key(sk).to_byte_type()
}
