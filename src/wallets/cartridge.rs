use std::{collections::HashMap, time::Duration, vec};

use account_sdk::{
    artifacts::DEFAULT_CONTROLLER,
    controller::Controller,
    factory::ControllerFactory,
    provider::CartridgeJsonRpcProvider,
    signers::{Owner, Signer},
};

use account_sdk::account::session::policy::Policy;
use actix_web::web;
use chrono::{DateTime, Utc};
use starknet::{
    accounts::{
        Account, AccountFactory, AccountFactoryError, ExecutionEncoding, SingleOwnerAccount,
    },
    core::{
        types::{Call, Felt, StarknetError},
        utils::cairo_short_string_to_felt,
    },
    macros::{felt, selector},
    providers::ProviderError,
    signers::{LocalWallet, SigningKey},
};
use tokio::time::sleep;
use url::Url;

use crate::{
    database::user_db::UserImpl,
    models::models::User,
    wallets::{
        helper::{
            build_approve_call, build_payment_call, build_payment_calldata,
            check_account_deployment_status, check_strk_balance, check_token_balance,
            create_failed_response, create_provider_from_url, estimate_transaction_gas,
            execute_transaction_with_receipt,
            get_or_create_controller_from_db, parse_felt_from_hex, serialize_u256_type,
            store_controller_in_db, validate_phone_format, validate_payment_inputs
        },
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
    pub fn new(app_state: web::Data<AppState>) -> Self {
        Self { app_state }
    }

    pub fn get_user_permissions(&self, user: &User) -> Vec<String> {
        let permission_config = PermissionConfig::new();
        permission_config.get_permissions_for_role(&user.role)
    }

    // Validate user exists and get their permissions
    pub fn validate_user_and_get_permissions(
        &self,
        phone: &str,
    ) -> Result<(User, Vec<String>), Box<dyn std::error::Error>> {
        let user = self
            .app_state
            .db
            .get_user_by_phone(&phone.to_string())
            .map_err(|e| format!("User not found: {:?}", e))?;

        let permissions = self.get_user_permissions(&user);

        if permissions.is_empty() {
            return Err(format!("No permission defined for role: {}", user.role).into());
        }

        Ok((user, permissions))
    }

    fn validate_user_input(
        &self,
        phone: &str,
        user_permissions: &[String],
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Email validation
        validate_phone_format(phone)?;

        // Permission validation
        let permission_config = PermissionConfig::new();
        for permission in user_permissions {
            if !permission_config.is_valid_permission(permission) {
                return Err(format!("Invalid permission: {}", permission).into());
            }
        }

        Ok(())
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

    pub fn create_owner_from_private_key(&self) -> Result<Owner, Box<dyn std::error::Error>> {
        let signing_key = SigningKey::from_secret_scalar(parse_felt_from_hex(
            &self.app_state.env.owner_private_key,
        )?);
        Ok(Owner::Signer(Signer::Starknet(signing_key)))
    }

    async fn verify_deployer_account(
        &self,
        deployer_address: Felt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let provider = create_provider_from_url(&self.app_state.env.starknet_rpc_url)?;

        check_strk_balance(provider.clone(), deployer_address).await?;

        if !check_account_deployment_status(&provider, deployer_address).await {
            return Err("Deployer account not deployed".into());
        }

        Ok(())
    }

    /// Generate controller factory and compute address
    fn create_controller_factory_and_address(
        &self,
        phone: &str,
        owner: Owner,
        provider: CartridgeJsonRpcProvider,
    ) -> Result<(ControllerFactory, Felt), Box<dyn std::error::Error>> {
        let chain_id = CHAIN_ID.clone();
        let salt = cairo_short_string_to_felt(phone)?;

        let factory = ControllerFactory::new(DEFAULT_CONTROLLER.hash, chain_id, owner, provider);

        let address = factory.address(salt);
        println!("Controller address for {}: {:#x}", phone, address);

        Ok((factory, address))
    }

    /// Fund controller only if needed
    async fn fund_controller_with_checks(
        &self,
        owner_account: &SingleOwnerAccount<CartridgeJsonRpcProvider, LocalWallet>,
        controller_address: Felt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let provider = create_provider_from_url(&self.app_state.env.starknet_rpc_url)?;
        // Check if controller is already deployed (funded controllers are typically deployed)
        if check_account_deployment_status(&provider, controller_address).await {
            println!("Controller already deployed, skipping funding");
            return Ok(());
        }

        println!("Funding controller address...");
        let funding_amount = felt!("500000000000000000");
        self.fund_controller_address(owner_account, controller_address, funding_amount)
            .await
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

    /// Deploy controller if not already deployed
    async fn deploy_controller_with_checks(
        &self,
        factory: ControllerFactory,
        salt: Felt,
        controller_address: Felt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let provider = create_provider_from_url(&self.app_state.env.starknet_rpc_url)?;

        // Check if controller is already deployed
        if check_account_deployment_status(&provider, controller_address).await {
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
                    let error_string = format!("{:?}", error_data);
                    if error_string.contains("Account already deployed") {
                        println!("Controller already deployed, skipping deployment");
                        return Ok(());
                    }
                }
                println!("Deployment failed: {:?}", e);
                Err(Box::new(e))
            }
        }
    }

    /// Generate session policies based on user permissions
    pub fn build_session_policies(
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

    pub async fn generate_session_policies(&self, user_permissions: &[String]) -> SessionPolicies {
        let mut methods = Vec::new();

        methods.push(ContractMethod {
            name: "Receive Payment".to_string(),
            entrypoint: "receive_payment".to_string(),
            description: Some("Receive payment from users to offramp".to_string()),
        });

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

        let message_policy = self.create_message_policy(chain_id);

        SessionPolicies {
            contract,
            messages: Some(vec![message_policy]),
        }
    }

    fn create_message_policy(&self, chain_id: Felt) -> SignMessagePolicy {
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

        SignMessagePolicy {
            name: Some("Kharon Pay Message Signing Policy".to_string()),
            description: Some("Allows signing messages for Kharon Pay transactions".to_string()),
            types,
            primary_type: "KharonPayMessage".to_string(),
            domain: StarknetDomain {
                name: "KharonPay".to_string(),
                version: "1".to_string(),
                chain_id: chain_id.to_string(),
                revision: "1".to_string(),
            },
        }
    }

    pub async fn create_controller(
        &self,
        phone: &str,
    ) -> Result<(Controller, String, SessionOptions), Box<dyn std::error::Error>> {
        let (user, user_permissions) = self.validate_user_and_get_permissions(phone)?;
        let database = &self.app_state.db;

        match get_or_create_controller_from_db(database, &self, &user.id, &user_permissions).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                log::info!("No valid controller session found, creating new one: {}", e);
            }
        }

        self.validate_user_input(phone, &user_permissions)?;
        let provider = create_provider_from_url(&self.app_state.env.starknet_rpc_url)?;
        let owner_account = self.create_owner_account(provider.clone())?;

        println!("Account address: {:#x}", owner_account.address());
        self.verify_deployer_account(owner_account.address())
            .await?;

        // Create factory and compute controller address
        let owner = self.create_owner_from_private_key()?;
        let salt = cairo_short_string_to_felt(&phone)?;
        let (factory, controller_address) =
            self.create_controller_factory_and_address(&phone, owner.clone(), provider.clone())?;

        // Fund controller address if needed - with 1 strk
        self.fund_controller_with_checks(&owner_account, controller_address)
            .await?;

        tokio::time::sleep(Duration::from_secs(3)).await;

        // Deploy controller if not already deployed
        self.deploy_controller_with_checks(factory, salt, controller_address)
            .await?;

        // Create controller with session
        let rpc_url = Url::parse(&self.app_state.env.starknet_rpc_url)?;
        let mut controller = Controller::new(
            self.app_state.env.app_id.clone(),
            phone.to_string(),
            DEFAULT_CONTROLLER.hash,
            rpc_url,
            owner.clone(),
            controller_address,
            CHAIN_ID.clone(),
        );

        let session_policies = self.generate_session_policies(&user_permissions).await;
        let contract_address = parse_felt_from_hex(&session_policies.contract)?;
        let policies = self.build_session_policies(&user_permissions, contract_address);

        // Set session expiration to 30 days
        let session_duration_seconds = 30 * 24 * 60 * 60; // 30 days
        let expires_at = (Utc::now().timestamp() + session_duration_seconds) as u64;

        log::info!(
            "Creating session with expiration: {} ({})",
            expires_at,
            DateTime::<Utc>::from_timestamp(expires_at as i64, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Invalid timestamp".to_string())
        );

        controller.create_session(policies, expires_at).await?;

        let session_options = SessionOptions {
            policies: session_policies,
            expires_at,
        };

        let username_str = phone.to_string();

        // Store in database
        store_controller_in_db(
            self,
            &database,
            &user.id,
            &username_str,
            &controller,
            &session_options,
            &user_permissions,
        )
        .await?;

        log::info!(
            "Controller created and stored successfully for user: {}",
            user.id
        );

        Ok((controller, username_str, session_options))
    }

    fn validate_payment_permission(&self, user_permissions: &[String]) -> Result<(), String> {
        if !user_permissions.contains(&"receive_payment".to_string()) {
            return Err("Insufficient permission to make payment".to_string());
        }

        Ok(())
    }

    async fn verify_sufficient_balance(
        &self,
        token: &str,
        user_address: Felt,
        required_amount: Felt,
    ) -> Result<(), String> {
        let token_felt =
            parse_felt_from_hex(token).map_err(|_| "Invalid token address".to_string())?;

        match check_token_balance(token_felt, user_address).await {
            Ok(user_balance) => {
                if user_balance < required_amount {
                    return Err(
                        "Insufficient token balance, please fund account and try again".to_string(),
                    );
                }
                Ok(())
            }
            Err(_) => Err("Failed to check user balance".to_string()),
        }
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
        if let Err(msg) = self.validate_payment_permission(user_permissions) {
            return Ok(create_failed_response("receive_payment", &msg));
        }

        let amount_felt = match validate_payment_inputs(reference, user_id, amount) {
            Ok(felt) => felt,
            Err(msg) => return Ok(create_failed_response("receive_payment", &msg)),
        };

        let token_address = match parse_felt_from_hex(token) {
            Ok(addr) => addr,
            Err(_) => {
                return Ok(create_failed_response(
                    "receive_payment",
                    "Invalid token address format",
                ))
            }
        };

        if let Err(msg) = self
            .verify_sufficient_balance(token, controller.address, amount_felt)
            .await
        {
            return Ok(create_failed_response("receive_payment", &msg));
        }

        let contract_address =
            match parse_felt_from_hex(&self.app_state.env.kharon_pay_contract_address) {
                Ok(addr) => addr,
                Err(_) => {
                    return Ok(create_failed_response(
                        "receive_payment",
                        "Invalid contract address",
                    ))
                }
            };

        self.execute_payment_transaction(
            controller,
            token_address,
            contract_address,
            amount_felt,
            reference,
            user_id,
        )
        .await
    }

    async fn execute_payment_transaction(
        &self,
        controller: &Controller,
        token_address: Felt,
        contract_address: Felt,
        amount_felt: Felt,
        reference: &str,
        user_id: &str,
    ) -> Result<TransactionResponse, Box<dyn std::error::Error>> {
        let (amount_low, amount_high) = serialize_u256_type(amount_felt);

        let approve_call =
            build_approve_call(token_address, contract_address, amount_low, amount_high);
        let payment_calldata =
            build_payment_calldata(token_address, amount_low, amount_high, reference, user_id);
        let payment_call = build_payment_call(contract_address, payment_calldata);

        let calls = vec![approve_call, payment_call];

        if let Err(msg) = estimate_transaction_gas(controller, calls.clone()).await {
            return Ok(create_failed_response("receive_payment", &msg));
        }

        execute_transaction_with_receipt(controller, calls.clone()).await
    }
}
