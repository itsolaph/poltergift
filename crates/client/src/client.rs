//! Transactions for Poltergift rounds, built with `ootle-rs` and submitted through an Ootle indexer.

use std::{collections::HashSet, num::NonZeroU64, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use ootle_rs::{
    Address, Epoch, Network, ToAccountAddress, TransactionOutcome, TransactionRequest,
    builtin_templates::{UnsignedTransactionBuilder, faucet::IFaucet},
    claim_burn::ClaimBurn,
    key_provider::PrivateKeyProvider,
    keys::OotleSecretKey,
    provider::{IndexerProvider, IndexerTrust, Provider, ProviderBuilder, WalletProvider, WantInput},
    stealth::{Output, StealthTransfer},
    transaction::ephemeral_signer::EphemeralKeySigner,
    wallet::OotleWallet,
};
use poltergift_ring::{self as ring, Purpose, SecretKey};
use tari_ootle_common_types::engine_types::{
    commit_result::ExecuteResult,
    substate::{SubstateId, SubstateValue},
    transaction_receipt::TransactionReceipt,
};
use tari_ootle_transaction::{Transaction, TransactionId, UnsignedTransaction, args};
use tari_template_lib_types::{
    Amount, ComponentAddress, TemplateAddress, UtxoAddress,
    constants::TARI_TOKEN,
    crypto::{PedersenCommitmentBytes, RistrettoPublicKeyBytes},
    stealth::StealthTransferStatement,
};

use crate::state::RoundState;

/// How far ahead (in epochs) a transaction may still be sequenced.
const VALIDITY_EPOCHS: u64 = 10;
/// The max fee a dry run is metered at. It must be within the paying account's balance.
const DRY_RUN_FEE: u64 = 2_000_000;
const TX_TIMEOUT: Duration = Duration::from_secs(180);
/// Right after an epoch change the indexer can still serve a proof from the previous epoch, which
/// the verifying provider rejects; it resolves itself once a block lands in the new epoch.
const EPOCH_RACE_RETRIES: u32 = 12;
const EPOCH_RACE_PAUSE: Duration = Duration::from_secs(10);

fn is_epoch_race(msg: &str) -> bool {
    msg.contains("whose validator set this provider anchored on") || msg.contains("has not yet served the checkpoint")
}

/// Parameters for a new round, in µT and epochs.
#[derive(Debug, Clone, Copy)]
pub struct RoundParams {
    pub gift_amount: u64,
    pub size: u32,
    pub join_deadline: u64,
    pub claim_deadline: u64,
    pub claim_fee: u64,
}

/// What a finalized transaction left behind.
#[derive(Debug, Clone)]
pub struct Finalized {
    pub tx_id: TransactionId,
    pub receipt: TransactionReceipt,
}

impl Finalized {
    pub fn fee_paid(&self) -> u64 {
        self.receipt.fee_receipt.total_fees_paid()
    }

    pub fn created_utxos(&self) -> Vec<PedersenCommitmentBytes> {
        self.receipt
            .diff_summary
            .upped
            .iter()
            .filter_map(|s| s.substate_id.as_utxo_address().map(|u| u.id().into_commitment_bytes()))
            .collect()
    }
}

/// A claim or refund that landed.
#[derive(Debug, Clone)]
pub struct Payout {
    pub finalized: Finalized,
    pub key_image: [u8; 32],
    pub output_commitment: PedersenCommitmentBytes,
}

pub struct PoltergiftClient {
    provider: IndexerProvider<OotleWallet>,
    secret: OotleSecretKey,
}

fn hex32(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

impl PoltergiftClient {
    /// Connects with full verification: every substate the indexer returns is checked against
    /// the validator set this provider trusts.
    pub async fn connect(indexer_url: &str, secret: OotleSecretKey) -> Result<Self> {
        Self::connect_with_trust(indexer_url, secret, IndexerTrust::Verify).await
    }

    pub async fn connect_with_trust(indexer_url: &str, secret: OotleSecretKey, trust: IndexerTrust) -> Result<Self> {
        let wallet = OotleWallet::from(PrivateKeyProvider::new(secret.clone()));
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .indexer_trust(trust)
            .connect_with_transaction_timeout(indexer_url, TX_TIMEOUT)
            .await
            .with_context(|| format!("connecting to indexer {indexer_url}"))?;
        let network = provider.get_network().await?;
        if network != secret.network() {
            bail!("indexer is on {network:?} but the wallet is for {:?}", secret.network());
        }
        Ok(Self { provider, secret })
    }

    pub fn network(&self) -> Network {
        self.provider.network()
    }

    pub fn address(&self) -> Address {
        self.secret.to_address()
    }

    pub fn account(&self) -> ComponentAddress {
        self.address().to_account_address()
    }

    pub fn provider(&self) -> &IndexerProvider<OotleWallet> {
        &self.provider
    }

    pub fn secret(&self) -> &OotleSecretKey {
        &self.secret
    }

    pub async fn epoch(&self) -> Result<u64> {
        Ok(self.provider.get_epoch().await?.as_u64())
    }

    async fn max_epoch(&self) -> Result<Epoch> {
        Ok(Epoch(self.epoch().await? + VALIDITY_EPOCHS))
    }

    pub async fn account_balance(&self) -> Result<Amount> {
        match self.provider.get_account_balance(self.account(), TARI_TOKEN).await {
            Ok(b) => Ok(b),
            Err(e) if e.to_string().contains("not found") || e.to_string().contains("NotFound") => Ok(Amount::zero()),
            Err(e) => Err(e.into()),
        }
    }

    // ---------------------------------------------------------------------------------------------
    // submission helpers
    // ---------------------------------------------------------------------------------------------

    async fn resolve(&self, unsigned: UnsignedTransaction, wants: &[WantInput]) -> Result<UnsignedTransaction> {
        let set: HashSet<WantInput> = wants.iter().cloned().collect();
        let mut attempt = 0;
        loop {
            match self.provider.resolve_input_want_list(unsigned.clone(), &set).await {
                Ok(tx) => return Ok(tx),
                Err(e) if is_epoch_race(&e.to_string()) && attempt < EPOCH_RACE_RETRIES => {
                    attempt += 1;
                    tokio::time::sleep(EPOCH_RACE_PAUSE).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    async fn submit(&mut self, tx: Transaction) -> Result<Finalized> {
        let pending = self.provider.send_transaction(tx).await?;
        let tx_id = pending.tx_id();
        let outcome = pending.watch().await.with_context(|| format!("waiting for {tx_id}"))?;
        match outcome {
            TransactionOutcome::Commit => {}
            TransactionOutcome::OnlyFeeCommit(reason) => {
                bail!("transaction {tx_id} failed after paying its fee: {reason}")
            }
            TransactionOutcome::Reject(reason) => bail!("transaction {tx_id} was rejected: {reason}"),
        }
        let receipt = pending.get_receipt().await?;
        Ok(Finalized { tx_id, receipt })
    }

    /// Account-paid transaction: dry-run at a generous max fee, then submit with the fee it reports.
    async fn submit_account_paid<F>(&mut self, build: F, wants: &[WantInput]) -> Result<Finalized>
    where
        F: Fn(u64, Epoch) -> UnsignedTransaction,
    {
        let max_epoch = self.max_epoch().await?;
        let mut wants = wants.to_vec();
        wants.push(WantInput::VaultForResource {
            component_address: self.account(),
            resource_address: TARI_TOKEN,
            required: true,
        });
        let dry = self.resolve(build(DRY_RUN_FEE, max_epoch), &wants).await?;
        let result = self.provider.sign_and_send_dry_run(dry).await?;
        let fee = required_fee(&result)?;
        let unsigned = self.resolve(build(fee, max_epoch), &wants).await?;
        let tx = TransactionRequest::default().with_transaction(unsigned).build(self.provider.wallet()).await?;
        self.submit(tx).await
    }

    // ---------------------------------------------------------------------------------------------
    // funding
    // ---------------------------------------------------------------------------------------------

    /// Takes the fixed faucet amount into this wallet's account (works where the faucet is funded,
    /// e.g. localnet).
    pub async fn take_faucet(&mut self) -> Result<Finalized> {
        let max_epoch = self.max_epoch().await?;
        let unsigned =
            IFaucet::new(&self.provider, max_epoch).take_faucet_funds().pay_fee(DRY_RUN_FEE).prepare().await?;
        let tx = TransactionRequest::default().with_transaction(unsigned).build(self.provider.wallet()).await?;
        self.submit(tx).await
    }

    /// Moves `amounts` from the account into fresh stealth outputs owned by `recipients` (one each).
    /// Returns the created output commitments in order.
    pub async fn send_stealth(
        &mut self,
        recipients: &[(Address, u64)],
    ) -> Result<(Finalized, Vec<PedersenCommitmentBytes>)> {
        let total: u64 = recipients.iter().map(|(_, a)| a).sum();
        let mut builder = StealthTransfer::new(TARI_TOKEN, &self.provider).spend_revealed_input(total);
        for (addr, amount) in recipients {
            let amount = NonZeroU64::new(*amount).ok_or_else(|| anyhow!("zero amount"))?;
            builder = builder.to_stealth_output(Output::new(addr.clone(), TARI_TOKEN, amount));
        }
        let (statement, _) = builder.prepare().await?;
        let commitments: Vec<_> = statement.stealth_outputs().iter().map(|o| *o.commitment()).collect();
        let account = self.account();
        let network = self.network();
        let finalized = self
            .submit_account_paid(
                |fee, max_epoch| {
                    Transaction::builder(network, max_epoch)
                        .with_auto_fill_inputs()
                        .pay_fee_from_component(account, fee)
                        .call_method(account, "withdraw", args![TARI_TOKEN, Amount::from(total)])
                        .put_last_instruction_output_on_workspace("funds")
                        .stealth_transfer_with_input_bucket(TARI_TOKEN, statement.clone(), "funds")
                        .build_unsigned()
                },
                &[],
            )
            .await?;
        Ok((finalized, commitments))
    }

    /// The key an L1 (minotari) burn must name as its claim public key for this wallet to claim it.
    pub fn burn_claim_public_key(&self) -> RistrettoPublicKeyBytes {
        use ootle_byte_type::ToByteType;
        use tari_crypto::keys::PublicKey as _;
        tari_crypto::ristretto::RistrettoPublicKey::from_secret_key(self.secret.account_secret()).to_byte_type()
    }

    /// Claims an L1 burn proof file (as the console wallet writes it with `--burn-proof-out`) into a fresh stealth output of this wallet. Returns the output and its value.
    pub async fn claim_burn(&mut self, proof_json: &str) -> Result<(Finalized, PedersenCommitmentBytes, u64)> {
        let (claim_proof, encrypted_data) = crate::burn_proof::parse_l1_burn_proof(proof_json)?;
        let max_epoch = self.max_epoch().await?;
        // The fee is revealed from the claimed funds and keeps no change, so measure it first.
        let (probe, sealer) = ClaimBurn::new(&self.provider, claim_proof.clone(), encrypted_data.clone(), max_epoch)
            .with_max_fee(200_000u64)
            .prepare()
            .await?;
        let dry = self.provider.sign_and_send_dry_run_with(&sealer, probe).await?;
        let fee = required_fee(&dry)?;
        let (unsigned, sealer) = ClaimBurn::new(&self.provider, claim_proof, encrypted_data, max_epoch)
            .with_max_fee(fee)
            .with_memo_message("poltergift: claimed L1 burn")
            .prepare()
            .await?;
        let tx = TransactionRequest::default().with_transaction(unsigned).build(&sealer).await?;
        let finalized = self.submit(tx).await?;
        let mut owned = None;
        for c in finalized.created_utxos() {
            if let Ok(Some(o)) = self.open_output(c).await {
                owned = Some((c, o.value));
            }
        }
        let (commitment, value) =
            owned.ok_or_else(|| anyhow!("claimed, but the new output does not open with this wallet"))?;
        Ok((finalized, commitment, value))
    }

    /// Moves `amount` from one of this wallet's stealth outputs into its account (creating the
    /// account if needed); change returns as a fresh stealth output.
    pub async fn deposit_to_account(
        &mut self,
        input: PedersenCommitmentBytes,
        input_value: u64,
        amount: u64,
    ) -> Result<Finalized> {
        let owner = self.burn_claim_public_key();
        // Pass 0 dry-runs with a generous budget to measure the fee; pass 1 submits with it. The fee
        // is part of the statement (revealed from the input), so the statement is rebuilt.
        let mut fee = 200_000u64.min(input_value.saturating_sub(amount + 1));
        for pass in 0..2 {
            let change =
                input_value.checked_sub(amount + fee).ok_or_else(|| anyhow!("input too small for amount + fee"))?;
            let mut builder = StealthTransfer::new(TARI_TOKEN, &self.provider)
                .spend_stealth_input(self.address(), input)
                .to_revealed_output(amount + fee);
            if let Some(change) = NonZeroU64::new(change) {
                builder = builder.to_stealth_output(Output::new(self.address(), TARI_TOKEN, change));
            }
            let (statement, signers) = builder.prepare().await?;
            let unsigned = Transaction::builder(self.network(), self.max_epoch().await?)
                .with_fee_instructions_builder(|b| {
                    b.stealth_transfer(TARI_TOKEN, statement.clone())
                        .put_last_instruction_output_on_workspace("funds")
                        .take_from_bucket("funds", Amount::from(amount), "deposit")
                        .pay_fee_from_bucket("funds")
                        .create_account_with_bucket(owner, "deposit")
                })
                .with_auto_fill_inputs()
                .add_input(TARI_TOKEN)
                .add_input(UtxoAddress::new(TARI_TOKEN, input.into()))
                .build_unsigned()
                .with_dry_run(pass == 0);
            let unsigned = self
                .resolve(
                    unsigned,
                    &[WantInput::SpecificSubstate { substate_id: self.account().into(), required: false }],
                )
                .await?;
            let authorizer = self.provider.wallet().stealth_authorizer(signers);
            let tx = TransactionRequest::default().with_transaction(unsigned).build(&authorizer).await?;
            if pass == 0 {
                fee = required_fee(&self.provider.send_dry_run(tx).await?)?;
            } else {
                return self.submit(tx).await;
            }
        }
        unreachable!("the second pass submits")
    }

    // ---------------------------------------------------------------------------------------------
    // template and round lifecycle
    // ---------------------------------------------------------------------------------------------

    pub async fn publish_template(&mut self, wasm: Vec<u8>) -> Result<(TemplateAddress, Finalized)> {
        let account = self.account();
        let network = self.network();
        let finalized = self
            .submit_account_paid(
                |fee, max_epoch| {
                    Transaction::builder(network, max_epoch)
                        .with_auto_fill_inputs()
                        .pay_fee_from_component(account, fee)
                        .publish_template(wasm.clone())
                        .build_unsigned()
                },
                &[],
            )
            .await?;
        let template = finalized
            .receipt
            .diff_summary
            .upped
            .iter()
            .find_map(|s| s.substate_id.as_template())
            .ok_or_else(|| anyhow!("no template address in receipt"))?;
        Ok((template.as_template_address(), finalized))
    }

    pub async fn create_round(
        &mut self,
        template: TemplateAddress,
        p: RoundParams,
    ) -> Result<(ComponentAddress, Finalized)> {
        let account = self.account();
        let network = self.network();
        let finalized = self
            .submit_account_paid(
                |fee, max_epoch| {
                    Transaction::builder(network, max_epoch)
                        .with_auto_fill_inputs()
                        .pay_fee_from_component(account, fee)
                        .call_function(
                            template,
                            "create",
                            args![
                                Amount::from(p.gift_amount),
                                p.size,
                                p.join_deadline,
                                p.claim_deadline,
                                Amount::from(p.claim_fee)
                            ],
                        )
                        .build_unsigned()
                },
                &[],
            )
            .await?;
        let component = finalized
            .receipt
            .diff_summary
            .upped
            .iter()
            .filter_map(|s| s.substate_id.as_component_address())
            .find(|c| *c != account)
            .ok_or_else(|| anyhow!("no round component in receipt"))?;
        Ok((component, finalized))
    }

    async fn fetch(&self, id: SubstateId) -> Result<tari_ootle_common_types::engine_types::substate::Substate> {
        let mut attempt = 0;
        loop {
            match self.provider.fetch_substate(id.clone()).await {
                Ok(s) => return Ok(s),
                Err(e) if is_epoch_race(&e.to_string()) && attempt < EPOCH_RACE_RETRIES => {
                    attempt += 1;
                    tokio::time::sleep(EPOCH_RACE_PAUSE).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub async fn round_state(&self, component: ComponentAddress) -> Result<RoundState> {
        let substate = self.fetch(component.into()).await?;
        match substate.into_substate_value() {
            SubstateValue::Component(c) => RoundState::from_value(c.state()),
            other => Err(anyhow!("{component} is not a component: {other:?}")),
        }
    }

    pub async fn vault_balance(&self, state: &RoundState) -> Result<Amount> {
        let substate = self.fetch(SubstateId::Vault(state.vault)).await?;
        match substate.into_substate_value() {
            SubstateValue::Vault(v) => Ok(v.balance()),
            other => Err(anyhow!("round vault is not a vault: {other:?}")),
        }
    }

    fn round_wants(component: ComponentAddress) -> Vec<WantInput> {
        vec![
            WantInput::SpecificSubstate { substate_id: component.into(), required: true },
            WantInput::AllComponentVaults { component_address: component },
            WantInput::SpecificSubstate { substate_id: TARI_TOKEN.into(), required: true },
        ]
    }

    /// Joins with a gift withdrawn from this wallet's account. Simple, but the join transaction is
    /// signed by the account key, so it links the account to the round (see `join_from_stealth`).
    pub async fn join_from_account(&mut self, component: ComponentAddress, member: &SecretKey) -> Result<Finalized> {
        let state = self.round_state(component).await?;
        let pop = ring::sign_pop(&state.round_id_bytes(), member, &mut rand::rng()).to_vec();
        let member_pk = RistrettoPublicKeyBytes::from(member.public_key());
        let gift = state.gift_amount;
        let account = self.account();
        let network = self.network();
        self.submit_account_paid(
            |fee, max_epoch| {
                Transaction::builder(network, max_epoch)
                    .with_auto_fill_inputs()
                    .pay_fee_from_component(account, fee)
                    .call_method(account, "withdraw", args![TARI_TOKEN, gift])
                    .put_last_instruction_output_on_workspace("gift")
                    .call_method(component, "join", args![member_pk, pop.clone(), Workspace("gift")])
                    .build_unsigned()
            },
            &Self::round_wants(component),
        )
        .await
    }

    /// Joins with a gift paid from one of this wallet's stealth outputs. The transaction is sealed by
    /// the output's one-time key and carries no account: an observer sees a stealth coin become a
    /// gift. Change goes back to this wallet as a fresh stealth output.
    pub async fn join_from_stealth(
        &mut self,
        component: ComponentAddress,
        member: &SecretKey,
        input: PedersenCommitmentBytes,
        input_value: u64,
    ) -> Result<Finalized> {
        let state = self.round_state(component).await?;
        let gift = u64::try_from(state.gift_amount.to_u128())?;
        let pop = ring::sign_pop(&state.round_id_bytes(), member, &mut rand::rng()).to_vec();
        let member_pk = RistrettoPublicKeyBytes::from(member.public_key());

        // First pass with a generous fee budget to learn the real fee; the budget is part of the
        // statement, so the final statement is rebuilt with the measured fee.
        let probe_budget = 200_000u64.min(input_value.saturating_sub(gift + 1));
        let (tx, _) =
            self.stealth_join_tx(component, &member_pk, &pop, input, input_value, gift, probe_budget, true).await?;
        let result = self.provider.send_dry_run(tx).await?;
        let fee = required_fee(&result)?;
        let (tx, _) = self.stealth_join_tx(component, &member_pk, &pop, input, input_value, gift, fee, false).await?;
        self.submit(tx).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn stealth_join_tx(
        &self,
        component: ComponentAddress,
        member_pk: &RistrettoPublicKeyBytes,
        pop: &[u8],
        input: PedersenCommitmentBytes,
        input_value: u64,
        gift: u64,
        fee: u64,
        dry_run: bool,
    ) -> Result<(Transaction, StealthTransferStatement)> {
        let change = input_value
            .checked_sub(gift + fee)
            .ok_or_else(|| anyhow!("stealth input of {input_value} µT cannot cover gift {gift} + fee {fee}"))?;
        let mut builder = StealthTransfer::new(TARI_TOKEN, &self.provider)
            .spend_stealth_input(self.address(), input)
            .to_revealed_output(gift + fee);
        if let Some(change) = NonZeroU64::new(change) {
            builder = builder.to_stealth_output(Output::new(self.address(), TARI_TOKEN, change));
        }
        let (statement, signers) = builder.prepare().await?;
        let max_epoch = self.max_epoch().await?;
        let unsigned = Transaction::builder(self.network(), max_epoch)
            .with_fee_instructions_builder(|b| {
                b.stealth_transfer(TARI_TOKEN, statement.clone())
                    .put_last_instruction_output_on_workspace("funds")
                    .take_from_bucket("funds", Amount::from(gift), "gift")
                    .pay_fee_from_bucket("funds")
                    .call_method(component, "join", args![*member_pk, pop.to_vec(), Workspace("gift")])
            })
            .with_auto_fill_inputs()
            .add_input(TARI_TOKEN)
            .add_input(UtxoAddress::new(TARI_TOKEN, input.into()))
            .build_unsigned()
            .with_dry_run(dry_run);
        let unsigned = self.resolve(unsigned, &Self::round_wants(component)).await?;
        let authorizer = self.provider.wallet().stealth_authorizer(signers);
        let tx = TransactionRequest::default().with_transaction(unsigned).build(&authorizer).await?;
        Ok((tx, statement))
    }

    /// Builds the payout statement: `amount` revealed in (from the round vault), one fresh stealth
    /// output to `to`.
    async fn payout_statement(&self, to: &Address, amount: Amount) -> Result<StealthTransferStatement> {
        let value = NonZeroU64::new(u64::try_from(amount.to_u128())?).ok_or_else(|| anyhow!("zero payout"))?;
        let (statement, _) = StealthTransfer::new(TARI_TOKEN, &self.provider)
            .spend_revealed_input(amount)
            .to_stealth_output(Output::new(to.clone(), TARI_TOKEN, value))
            .prepare()
            .await?;
        Ok(statement)
    }

    /// Claims one gift of `component` as `member`, paid to a fresh stealth output for `to`.
    /// The transaction is sealed by a throwaway key and its fee is paid by the round vault, so
    /// nothing in it points at this wallet or at the member's position in the ring.
    pub async fn claim(&mut self, component: ComponentAddress, member: &SecretKey, to: &Address) -> Result<Payout> {
        let state = self.round_state(component).await?;
        if !state.is_sealed() {
            bail!("round is not sealed yet ({}/{} joined)", state.members.len(), state.size);
        }
        let index =
            state.member_index(&member.public_key()).ok_or_else(|| anyhow!("this member key is not in the round"))?;
        let statement = self.payout_statement(to, state.payout_amount()).await?;
        let message = ring::payout_message(&tari_bor::encode(&statement)?);
        let (signature, key_image) = ring::sign(
            Purpose::Claim,
            &state.round_id_bytes(),
            &state.ring(),
            index,
            member,
            &message,
            &mut rand::rng(),
        )
        .map_err(|e| anyhow!("signing claim: {e}"))?;
        let output_commitment = *statement.stealth_outputs()[0].commitment();
        let image = RistrettoPublicKeyBytes::from(key_image);
        let sig = signature.to_bytes();
        let unsigned = Transaction::builder(self.network(), self.max_epoch().await?)
            .with_fee_instructions_builder(|b| b.call_method(component, "claim", args![image, sig, statement]))
            .with_auto_fill_inputs()
            .build_unsigned();
        let finalized = self.submit_ephemeral(unsigned, component).await?;
        Ok(Payout { finalized, key_image, output_commitment })
    }

    /// Takes a member's gift back after the relevant deadline.
    pub async fn refund(&mut self, component: ComponentAddress, member: &SecretKey, to: &Address) -> Result<Payout> {
        let state = self.round_state(component).await?;
        let statement = self.payout_statement(to, state.payout_amount()).await?;
        let message = ring::payout_message(&tari_bor::encode(&statement)?);
        let public = member.public_key();
        let (proof, key_image) =
            ring::sign(Purpose::Refund, &state.round_id_bytes(), &[public], 0, member, &message, &mut rand::rng())
                .map_err(|e| anyhow!("signing refund: {e}"))?;
        let output_commitment = *statement.stealth_outputs()[0].commitment();
        let member_pk = RistrettoPublicKeyBytes::from(public);
        let image = RistrettoPublicKeyBytes::from(key_image);
        let proof = proof.to_bytes();
        let unsigned = Transaction::builder(self.network(), self.max_epoch().await?)
            .with_fee_instructions_builder(|b| {
                b.call_method(component, "refund", args![member_pk, image, proof, statement])
            })
            .with_auto_fill_inputs()
            .build_unsigned();
        let finalized = self.submit_ephemeral(unsigned, component).await?;
        Ok(Payout { finalized, key_image, output_commitment })
    }

    /// Seals with a fresh throwaway key after a dry run, so a bad claim fails before submission.
    async fn submit_ephemeral(
        &mut self,
        unsigned: UnsignedTransaction,
        component: ComponentAddress,
    ) -> Result<Finalized> {
        let unsigned = self.resolve(unsigned, &Self::round_wants(component)).await?;
        let dry = EphemeralKeySigner::random().seal_transaction(unsigned.clone().with_dry_run(true).finish());
        let result = self.provider.send_dry_run(dry).await?;
        if let Some(reason) = result.finalize.any_reject() {
            bail!("rejected in dry run: {reason}");
        }
        let tx = EphemeralKeySigner::random().seal_transaction(unsigned.finish());
        self.submit(tx).await
    }
}

/// The fee to carry, from a dry run. A transaction's compute allowance is bought by the fee it
/// carries (1 µT per 1000 points on the current fee table), and intrinsic-heavy calls use more
/// compute than the charged-fee floor reflects, so the fee covers whichever is larger, with margin.
fn required_fee(result: &ExecuteResult) -> Result<u64> {
    if let Some(reason) = result.finalize.any_reject() {
        bail!("rejected in dry run: {reason}");
    }
    let floor = result.finalize.required_fees();
    let points = result.wasm_execution_points + result.native_execution_points;
    let compute = points.div_ceil(1000);
    // Dry runs have been seen to under-report execution points for intrinsic-heavy calls, and a
    // short allowance fails the transaction after its fee is taken; account-paid fees refund any
    // excess, so the margin is generous.
    Ok(floor.max(compute) * 2 + 5_000)
}

/// Hex helper used by the CLI output.
pub fn hex_key(bytes: &[u8; 32]) -> String {
    hex32(bytes)
}
