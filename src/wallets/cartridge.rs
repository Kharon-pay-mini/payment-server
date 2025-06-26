use std::{collections::HashMap, time::Duration, vec};

use account_sdk::{
    artifacts::{Version, CONTROLLERS, DEFAULT_CONTROLLER},
    controller::Controller,
    factory::ControllerFactory,
    provider::CartridgeJsonRpcProvider,
    signers::{Owner, Signer},
};

use account_sdk::account::session::policy::Policy;
use actix_web::web;
use base64::encode;
use starknet::{
    accounts::{
        Account, AccountFactory, AccountFactoryError, ConnectedAccount, ExecutionEncoding,
        OpenZeppelinAccountFactory, SingleOwnerAccount,
    },
    core::{
        chain_id,
        types::{
            BlockId, BlockTag, Call, Felt, FunctionCall, StarknetError, TransactionExecutionStatus,
            TransactionReceipt, TransactionReceiptWithBlockInfo,
        },
        utils::{cairo_short_string_to_felt, get_selector_from_name},
    },
    macros::{felt, selector},
    providers::{Provider, ProviderError},
    signers::{LocalWallet, SigningKey},
};
use tokio::time::sleep;
use url::Url;

use crate::{
    database::user_db::UserImpl,
    models::models::User,
    wallets::{
        helper::{encode_bytearray, get_detailed_error},
        models::{
            ContractMethod, SessionOptions, SessionPolicies, SignMessagePolicy, StarknetDomain,
            StarknetType, TransactionResponse,
        },
    },
    AppState,
};

pub struct ControllerService {
    app_state: web::Data<AppState>,
}

pub struct PermissionConfig {
    pub role_permissions: HashMap<String, Vec<String>>,
}

const CHAIN_ID: Felt = felt!("0x534e5f5345504f4c4941"); // Hex for "SN_SEPOLIA"
                                                        // let chain_id = felt!("0x534e5f4d41494e"); // Hex for "SN_MAIN"

impl PermissionConfig {
    pub fn new() -> Self {
        let mut role_permissions = HashMap::new();

        role_permissions.insert(
            "admin".to_string(),
            vec![
                "receive_payment".to_string(),
                "add_supported_token".to_string(),
                "remove_supported_token".to_string(),
                "withdraw".to_string(),
                "pause_system".to_string(),
                "unpause_system".to_string(),
                "create_controller".to_string(),
            ],
        );

        role_permissions.insert(
            "user".to_string(),
            vec![
                "receive_payment".to_string(),
                "transfer".to_string(),
                "balance_of".to_string(),
                "get_supported_tokens".to_string(),
                "create_controller".to_string(),
            ],
        );

        Self { role_permissions }
    }

    pub fn get_permissions_for_role(&self, role: &str) -> Vec<String> {
        self.role_permissions.get(role).cloned().unwrap_or_else(|| {
            println!("Role '{}' not found, returning empty permissions", role);
            vec![]
        })
    }

    pub fn is_valid_permission(&self, permission: &str) -> bool {
        self.role_permissions
            .values()
            .any(|perms| perms.contains(&permission.to_string()))
    }
}

impl ControllerService {
    pub fn get_user_permissions(&self, user: &User) -> Vec<String> {
        let permission_config = PermissionConfig::new();
        permission_config.get_permissions_for_role(&user.role)
    }

    // Validate user exists and get their permissions
    pub fn validate_user_and_get_permissions(
        &self,
        user_email: &str,
    ) -> Result<(User, Vec<String>), Box<dyn std::error::Error>> {
        let user = self
            .app_state
            .db
            .get_user_by_email(user_email.to_string())
            .map_err(|e| format!("User not found: {:?}", e))?;

        let permissions = self.get_user_permissions(&user);

        if permissions.is_empty() {
            return Err(format!("No permission defined for role: {}", user.role).into());
        }

        Ok((user, permissions))
    }

    pub fn new(app_state: web::Data<AppState>) -> Self {
        Self { app_state }
    }

    fn extract_username(&self, email: &str) -> String {
        email.split('@').next().unwrap_or(email).to_string()
    }
    async fn generate_session_policies(&self, user_permissions: &[String]) -> SessionPolicies {
        let mut methods = Vec::new();

        methods.extend(vec![ContractMethod {
            name: "Receive Payment".to_string(),
            entrypoint: "receive_payment".to_string(),
            description: Some("Receive payment from users to offramp".to_string()),
        }]);

        if user_permissions.contains(&"admin".to_string()) {
            methods.extend(vec![
                ContractMethod {
                    name: "Add Supported Token".to_string(),
                    entrypoint: "add_supported_token".to_string(),
                    description: Some("Add a new supported token".to_string()),
                },
                ContractMethod {
                    name: "Remove Supported Token".to_string(),
                    entrypoint: "remove_supported_token".to_string(),
                    description: Some("Remove a supported token".to_string()),
                },
                ContractMethod {
                    name: "Withdraw".to_string(),
                    entrypoint: "withdraw".to_string(),
                    description: Some("Withdraw tokens from the contract".to_string()),
                },
                ContractMethod {
                    name: "Pause System".to_string(),
                    entrypoint: "pause_system".to_string(),
                    description: Some("Pause the payment system".to_string()),
                },
                ContractMethod {
                    name: "Unpause System".to_string(),
                    entrypoint: "unpause_system".to_string(),
                    description: Some("Unpause the payment system".to_string()),
                },
            ]);
        }

        let contract = self.app_state.env.kharon_pay_contract_address.clone();
        let chain_id = CHAIN_ID.clone();

        let message_policy = SignMessagePolicy {
            name: Some("Kharon Pay Message Signing Policy".to_string()),
            description: Some("Allows signing messages for Kharon Pay transactions".to_string()),
            types: {
                let mut types = HashMap::new();
                types.insert(
                    "StarknetDomain".to_string(),
                    vec![
                        StarknetType {
                            name: "name".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                        StarknetType {
                            name: "version".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                        StarknetType {
                            name: "chainId".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                        StarknetType {
                            name: "revision".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                    ],
                );
                types.insert(
                    "KharonPayMessage".to_string(),
                    vec![
                        StarknetType {
                            name: "user".to_string(),
                            type_name: "ContractAddress".to_string(),
                        },
                        StarknetType {
                            name: "action".to_string(),
                            type_name: "shortstring".to_string(),
                        },
                        StarknetType {
                            name: "amount".to_string(),
                            type_name: "felt".to_string(),
                        },
                        StarknetType {
                            name: "token".to_string(),
                            type_name: "ContractAddress".to_string(),
                        },
                        StarknetType {
                            name: "timestamp".to_string(),
                            type_name: "felt".to_string(),
                        },
                        StarknetType {
                            name: "nonce".to_string(),
                            type_name: "felt".to_string(),
                        },
                    ],
                );
                types
            },
            primary_type: "KharonPayMessage".to_string(),
            domain: StarknetDomain {
                name: "KharonPay".to_string(),
                version: "1".to_string(),
                chain_id: chain_id.to_string(),
                revision: "1".to_string(),
            },
        };

        SessionPolicies {
            contract,
            messages: Some(vec![message_policy]),
        }
    }

    async fn check_deployer_balance_and_deployment_status(
        &self,
        deployer_address: Felt,
    ) -> Result<Felt, Box<dyn std::error::Error>> {
        let rpc_url: Url = Url::parse(&self.app_state.env.starknet_rpc_url)?;
        let provider = CartridgeJsonRpcProvider::new(rpc_url.clone());

        let strk_token_contract =
            felt!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");
        match provider
            .call(
                FunctionCall {
                    contract_address: strk_token_contract,
                    entry_point_selector: get_selector_from_name("balanceOf").unwrap(),
                    calldata: vec![deployer_address],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
        {
            Ok(balance_result) => {
                let balance = balance_result[0];
                if balance == Felt::ZERO {
                    return Err(format!(
                        "Deployer account {} has zero STRK balance. Please fund.",
                        format!("{:#x}", deployer_address)
                    )
                    .into());
                }
                println!("STRK balance of deployer: {}", balance);
            }
            Err(e) => {
                println!("Failed to check deployer account balance: {:?}", e);
            }
        }

        // Check if the account is already deployed
        match provider
            .get_nonce(BlockId::Tag(BlockTag::Latest), deployer_address)
            .await
        {
            Ok(_) => {
                println!("Deployer account already deployed");
                return Ok(deployer_address);
            }
            Err(e) => {
                println!("Deployer account not deployed, deploying now...");
                Err(Box::new(e))
            }
        }
    }

    async fn check_token_balance_of_user(
        &self,
        token: &str,
        user_address: Felt,
    ) -> Result<Felt, Box<dyn std::error::Error>> {
        let rpc_url: Url = Url::parse(&self.app_state.env.starknet_rpc_url)?;
        let provider = CartridgeJsonRpcProvider::new(rpc_url.clone());

        let token_felt = Felt::from_hex(token)?;
        match provider
            .call(
                FunctionCall {
                    contract_address: token_felt,
                    entry_point_selector: get_selector_from_name("balance_of").unwrap(),
                    calldata: vec![user_address],
                },
                BlockId::Tag(BlockTag::Latest),
            )
            .await
        {
            Ok(balance_result) => {
                let balance = balance_result[0];
                if balance == Felt::ZERO {
                    return Err(format!(
                        "User account {} has zero balance for token {}. Please fund.",
                        user_address, token
                    )
                    .into());
                }
                println!("Token balance of user: {}", balance);
                Ok(balance)
            }
            Err(e) => {
                println!("Failed to check user account balance: {:?}", e);
                Err(format!("Failed to check balance: {:?}", e).into())
            }
        }
    }

    async fn fund_controller_address(
        &self,
        argent_account: &SingleOwnerAccount<CartridgeJsonRpcProvider, LocalWallet>,
        controller_address: Felt,
        amount: Felt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let strk_token_contract =
            felt!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

        println!(
            "Funding controller address {:#x} with {} STRK",
            controller_address, amount
        );

        let transfer_call = Call {
            to: strk_token_contract,
            selector: selector!("transfer"),
            calldata: vec![controller_address, amount, felt!("0x0")],
        };

        match argent_account.execute_v3(vec![transfer_call]).send().await {
            Ok(result) => {
                println!(
                    "Funding successful! Transaction hash: {:#x}",
                    result.transaction_hash
                );

                sleep(Duration::from_secs(10)).await; // Wait for the transaction to be confirmed
                Ok(())
            }
            Err(e) => {
                println!("Funding failed: {:?}", e);
                Err(Box::new(e))
            }
        }
    }

    async fn check_controller_is_deployed(&self, controller_address: Felt) -> bool {
        let rpc_url: Url =
            Url::parse(&self.app_state.env.starknet_rpc_url).expect("Invalid RPC URL");
        let provider = CartridgeJsonRpcProvider::new(rpc_url);

        match provider
            .get_nonce(BlockId::Tag(BlockTag::Latest), controller_address)
            .await
        {
            Ok(_) => {
                println!(
                    "Controller at {:#x} is already deployed",
                    controller_address
                );
                true
            }
            Err(e) => {
                println!(
                    "Controller at {:#x} is not deployed: {:?}",
                    controller_address, e
                );
                false
            }
        }
    }

    fn validate_user_input(
        &self,
        user_email: &str,
        user_permissions: &[String],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Email validation
        if user_email.is_empty() || !user_email.contains('@') {
            return Err("Invalid email format".into());
        }

        // Username length validation
        let username = self.extract_username(user_email);
        if username.is_empty() || username.len() > 31 {
            return Err("Username must be between 1-31 characters".into());
        }

        // Permission validation
        let permission_config = PermissionConfig::new();
        for permission in user_permissions {
            if !permission_config.is_valid_permission(permission) {
                return Err(format!("Invalid permission: {}", permission).into());
            }
        }

        Ok(())
    }

    /// Create and configure the provider
    fn create_provider(&self) -> Result<CartridgeJsonRpcProvider, Box<dyn std::error::Error>> {
        let rpc_url: Url =
            Url::parse(&self.app_state.env.starknet_rpc_url).map_err(|_| "Invalid RPC URL")?;
        Ok(CartridgeJsonRpcProvider::new(rpc_url))
    }

    /// Create the owner account
    fn create_owner_account(
        &self,
        provider: CartridgeJsonRpcProvider,
    ) -> Result<SingleOwnerAccount<CartridgeJsonRpcProvider, LocalWallet>, Box<dyn std::error::Error>>
    {
        let chain_id = CHAIN_ID.clone();
        let owner_address = Felt::from_hex(&self.app_state.env.owner_address)?;
        let signer =
            SigningKey::from_secret_scalar(Felt::from_hex(&self.app_state.env.owner_private_key)?);
        let wallet = LocalWallet::from(signer.clone());

        let account = SingleOwnerAccount::new(
            provider,
            wallet,
            owner_address,
            chain_id,
            ExecutionEncoding::New,
        );

        Ok(account)
    }

    /// Generate controller factory and compute address
    fn create_controller_factory_and_address(
        &self,
        username: &str,
        owner: Owner,
        provider: CartridgeJsonRpcProvider,
    ) -> Result<(ControllerFactory, Felt), Box<dyn std::error::Error>> {
        let chain_id = CHAIN_ID.clone();
        let salt = cairo_short_string_to_felt(username)?;

        let factory = ControllerFactory::new(DEFAULT_CONTROLLER.hash, chain_id, owner, provider);

        let address = factory.address(salt);
        println!("Controller address for {}: {:#x}", username, address);

        Ok((factory, address))
    }

    /// Deploy controller if not already deployed
    async fn deploy_controller(
        &self,
        factory: ControllerFactory,
        salt: Felt,
        controller_address: Felt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check if controller is already deployed
        if self.check_controller_is_deployed(controller_address).await {
            println!("Controller already deployed, skipping deployment");
            return Ok(());
        }

        println!("Controller not deployed, proceeding with deployment...");

        match factory
            .deploy_v3(salt)
            .gas_estimate_multiplier(1.5)
            .send()
            .await
        {
            Ok(_) => {
                println!("Controller deployed successfully");
                Ok(())
            }
            Err(e) => {
                if let AccountFactoryError::Provider(ProviderError::StarknetError(
                    StarknetError::TransactionExecutionError(ref error_data),
                )) = e
                {
                    if error_data
                        .execution_error
                        .contains("is unavailable for deployment")
                    {
                        println!("Controller already deployed (detected during deployment), continuing...");
                        return Ok(());
                    }
                }
                println!("Deployment failed: {:?}", e);
                Err(Box::new(e))
            }
        }
    }

    /// Fund controller only if needed
    async fn fund_controller_with_checks(
        &self,
        owner_account: &SingleOwnerAccount<CartridgeJsonRpcProvider, LocalWallet>,
        controller_address: Felt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Check if controller is already deployed (funded controllers are typically deployed)
        if self.check_controller_is_deployed(controller_address).await {
            println!("Controller already deployed, skipping funding");
            return Ok(());
        }

        println!("Funding controller address...");
        let funding_amount = felt!("1000000000000000000");
        self.fund_controller_address(owner_account, controller_address, funding_amount)
            .await
    }

    /// Generate session policies based on user permissions
    fn build_session_policies(
        &self,
        user_permissions: &[String],
        contract_address: Felt,
    ) -> Vec<Policy> {
        let mut policies = Vec::new();

        // Base policy for all users
        policies.push(Policy::new_call(
            contract_address,
            selector!("receive_payment"),
        ));

        // Admin-specific policies
        if user_permissions.contains(&"admin".to_string()) {
            policies.extend(vec![
                Policy::new_call(contract_address, selector!("add_supported_token")),
                Policy::new_call(contract_address, selector!("remove_supported_token")),
                Policy::new_call(contract_address, selector!("withdraw")),
                Policy::new_call(contract_address, selector!("pause_system")),
                Policy::new_call(contract_address, selector!("unpause_system")),
            ]);
        }

        policies
    }

    pub async fn create_controller(
        &self,
        user_email: &str,
    ) -> Result<(Controller, String, SessionOptions), Box<dyn std::error::Error>> {
        let (user, user_permissions) = self.validate_user_and_get_permissions(user_email)?;

        self.validate_user_input(user_email, &user_permissions)?;

        let username = self.extract_username(user_email);

        let provider = self.create_provider()?;
        let owner_account = self.create_owner_account(provider.clone())?;
        println!("Account address: {:#x}", owner_account.address());

        self.check_deployer_balance_and_deployment_status(owner_account.address())
            .await?;

        //create factory and compute controller address
        let owner = Owner::Signer(Signer::Starknet(SigningKey::from_secret_scalar(
            Felt::from_hex(&self.app_state.env.owner_private_key)?,
        )));

        let salt = cairo_short_string_to_felt(&username)?;
        let (factory, controller_address) =
            self.create_controller_factory_and_address(&username, owner.clone(), provider.clone())?;

        // fund controller address if needed- with 1 strk
        self.fund_controller_with_checks(&owner_account, controller_address)
            .await?;

        // deploy controller if not already deployed
        self.deploy_controller(factory, salt, controller_address)
            .await?;

        let rpc_url = Url::parse(&self.app_state.env.starknet_rpc_url)?;
        let mut controller = Controller::new(
            self.app_state.env.app_id.clone(),
            username.clone(),
            DEFAULT_CONTROLLER.hash,
            rpc_url,
            owner.clone(),
            controller_address,
            CHAIN_ID.clone(),
        );

        let session_policies = self.generate_session_policies(&user_permissions).await;
        let contract_address = Felt::from_hex(&session_policies.contract)?;

        let policies = self.build_session_policies(&user_permissions, contract_address);

        let _ = controller.create_session(policies, u32::MAX as u64).await?;

        let session_options = SessionOptions {
            policies: session_policies,
            expires_at: u32::MAX as u64,
        };

        Ok((controller, username.clone(), session_options))
    }

    pub async fn receive_payment(
        &self,
        controller: &Controller,
        token: &str,
        amount: &str,
        reference: &str,
        user_id: &str,
        user_permissions: &[String],
    ) -> Result<TransactionResponse, Box<dyn std::error::Error>> {
        // Validate user permissions
        if !user_permissions.contains(&"receive_payment".to_string()) {
            return Ok(TransactionResponse {
                transaction_hash: "0x0".to_string(),
                status: "failed".to_string(),
                function_called: "receive_payment".to_string(),
                message: Some("Insufficient permission".to_string()),
            });
        }

        // Validate inputs match Cairo contract requirements
        if reference.is_empty() {
            return Ok(TransactionResponse {
                transaction_hash: "0x0".to_string(),
                status: "failed".to_string(),
                function_called: "receive_payment".to_string(),
                message: Some("Reference cannot be empty".to_string()),
            });
        }

        if user_id.is_empty() {
            return Ok(TransactionResponse {
                transaction_hash: "0x0".to_string(),
                status: "failed".to_string(),
                function_called: "receive_payment".to_string(),
                message: Some("User ID cannot be empty".to_string()),
            });
        }

        match self
            .check_token_balance_of_user(token, controller.address)
            .await
        {
            Ok(user_balance) => {
                let amount_felt = if amount.starts_with("0x") {
                    Felt::from_hex(amount).map_err(|_| "Invalid hex amount format")?
                } else {
                    Felt::from_dec_str(amount).map_err(|_| "Invalid decimal amount format")?
                };

                if user_balance < amount_felt {
                    println!("Insufficient token balance for user");
                    return Ok(TransactionResponse {
                        transaction_hash: "0x0".to_string(),
                        status: "failed".to_string(),
                        function_called: "receive_payment".to_string(),
                        message: Some(
                            "Insufficient balance, please fund your account and try again"
                                .to_string(),
                        ),
                    });
                }
            }
            Err(e) => {
                println!("Failed to check user balance: {}", e);
                return Ok(TransactionResponse {
                    transaction_hash: "0x0".to_string(),
                    status: "failed".to_string(),
                    function_called: "receive_payment".to_string(),
                    message: Some("Failed to check user balance".to_string()),
                });
            }
        }

        let contract_address = Felt::from_hex(&self.app_state.env.kharon_pay_contract_address)
            .map_err(|_| "Invalid contract address")?;

        let token_address = Felt::from_hex(token).map_err(|_| "Invalid token address format")?;

        // Parse amount as u256 (your contract expects u256)
        let amount_felt = if amount.starts_with("0x") {
            Felt::from_hex(amount).map_err(|_| "Invalid hex amount format")?
        } else {
            Felt::from_dec_str(amount).map_err(|_| "Invalid decimal amount format")?
        };

        // Encode strings as ByteArray
        let reference_bytearray = encode_bytearray(reference);
        let user_bytearray = encode_bytearray(user_id);

        // Build calldata in correct order
        let mut calldata = Vec::new();
        calldata.push(token_address); // ContractAddress
        calldata.push(amount_felt); // u256 (low part)
        calldata.push(Felt::ZERO); // u256 (high part - assuming amount fits in felt)
        calldata.extend(reference_bytearray); // ByteArray
        calldata.extend(user_bytearray); // ByteArray

        println!("Final calldata: {:?}", calldata);
        println!("Calldata length: {}", calldata.len());

        let call = Call {
            to: contract_address,
            selector: selector!("receive_payment"),
            calldata,
        };

        // Estimate gas
        match controller.estimate_invoke_fee(vec![call.clone()]).await {
            Ok(fee_estimate) => {
                println!("Gas estimation successful: {:?}", fee_estimate);
            }
            Err(e) => {
                let detailed_error = get_detailed_error(&e).await;
                println!("Gas estimation failed: {}", detailed_error);
                return Ok(TransactionResponse {
                    transaction_hash: "0x0".to_string(),
                    status: "failed".to_string(),
                    function_called: "receive_payment".to_string(),
                    message: Some(format!("Gas estimation failed: {}", detailed_error)),
                });
            }
        }

        // Execute transaction
        match controller.execute_v3(vec![call]).send().await {
            Ok(result) => {
                println!(
                    "Transaction sent successfully: {:#x}",
                    result.transaction_hash
                );

                // Wait for transaction receipt
                let receipt_result = controller
                    .provider()
                    .get_transaction_receipt(result.transaction_hash)
                    .await;

                match receipt_result {
                    Ok(receipt) => {
                        println!("Transaction receipt: {:?}", receipt);

                        let revert_message;
                        let (status, status_message) = match &receipt.receipt {
                            TransactionReceipt::Invoke(invoke_receipt) => {
                                match invoke_receipt.execution_result.status() {
                                    TransactionExecutionStatus::Succeeded => {
                                        ("success", "Payment processed successfully")
                                    }
                                    TransactionExecutionStatus::Reverted => {
                                        let revert_reason = invoke_receipt
                                            .execution_result
                                            .revert_reason()
                                            .unwrap_or("Unknown revert reason");
                                        revert_message =
                                            format!("Transaction reverted: {}", revert_reason);
                                        ("failed", revert_message.as_str())
                                    }
                                }
                            }
                            _ => ("success", "Transaction completed"),
                        };

                        Ok(TransactionResponse {
                            transaction_hash: format!("{:#x}", result.transaction_hash),
                            status: status.to_string(),
                            function_called: "receive_payment".to_string(),
                            message: Some(status_message.to_string()),
                        })
                    }
                    Err(e) => {
                        let detailed_error = get_detailed_error(&e).await;
                        println!("Receipt fetch failed: {}", detailed_error);
                        Ok(TransactionResponse {
                            transaction_hash: format!("{:#x}", result.transaction_hash),
                            status: "pending".to_string(),
                            function_called: "receive_payment".to_string(),
                            message: Some("Transaction sent but status unknown".to_string()),
                        })
                    }
                }
            }
            Err(e) => {
                let detailed_error = get_detailed_error(&e).await;
                println!("Transaction execution failed: {}", detailed_error);

                Ok(TransactionResponse {
                    transaction_hash: "0x0".to_string(),
                    status: "failed".to_string(),
                    function_called: "receive_payment".to_string(),
                    message: Some(format!("Transaction failed: {}", detailed_error)),
                })
            }
        }
    }
}
