use std::{
    env,
    thread::sleep,
    time::{Duration, Instant},
};

use crate::{
    database::{db::Database, user_wallet_db::UserWalletImpl},
    models::models::{ControllerSessionInfo, PolicyList},
    wallets::cartridge::ControllerService,
    AppState,
};
use account_sdk::{
    artifacts::DEFAULT_CONTROLLER, controller::Controller, provider::CartridgeJsonRpcProvider,
    signers::Owner,
};
use actix_web::web;
use chrono::{DateTime, Utc};
use starknet::{
    accounts::{Account, ConnectedAccount},
    core::types::{
        BlockId, BlockTag, Call, Felt, FunctionCall, TransactionExecutionStatus,
        TransactionReceipt, TransactionReceiptWithBlockInfo,
    },
    macros::{felt, selector},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};
use url::Url;

use crate::wallets::models::{SessionOptions, TransactionResponse};

const CHAIN_ID: Felt = felt!("0x534e5f5345504f4c4941"); // Hex for "SN_SEPOLIA"
                                                        // let chain_id = felt!("0x534e5f4d41494e"); // Hex for "SN_MAIN"

pub async fn get_detailed_error(error: &dyn std::error::Error) -> String {
    let error_string = error.to_string();

    if error_string.contains("CONTRACT_NOT_FOUND") {
        return "Contract not found - check contract address".to_string();
    }

    if error_string.contains("ENTRY_POINT_NOT_FOUND") {
        return "Function 'receive_payment' not found in contract".to_string();
    }

    if error_string.contains("INSUFFICIENT_ACCOUNT_BALANCE") {
        return "Insufficient account balance for transaction fee".to_string();
    }

    if error_string.contains("INVALID_TRANSACTION_NONCE") {
        return "Invalid transaction nonce - account state issue".to_string();
    }

    if error_string.contains("TRANSACTION_EXECUTION_ERROR") {
        return "Contract execution failed - check function parameters and contract state"
            .to_string();
    }

    if error_string.contains("VALIDATE_FAILURE") {
        return "Transaction validation failed - check account permissions".to_string();
    }

    if error_string.contains("ACTUAL_FEE_EXCEEDED_MAX_FEE") {
        return "Transaction fee exceeded maximum allowed fee".to_string();
    }

    format!("Execution error: {}", error_string)
}

pub fn encode_bytearray(input: &str) -> Vec<Felt> {
    let bytes = input.as_bytes();

    if bytes.is_empty() {
        return vec![Felt::ZERO, Felt::ZERO, Felt::ZERO];
    }

    if bytes.len() <= 31 {
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(bytes);

        return vec![
            Felt::ZERO,                     // data.len()
            Felt::from_bytes_be(&padded),   //pending word
            Felt::from(bytes.len() as u64), //pending word len
        ];
    }

    let full_chunks = bytes.len() / 31;
    let remaining_bytes = bytes.len() % 31;
    let mut result = Vec::new();

    result.push(Felt::from(full_chunks as u64));

    for i in 0..full_chunks {
        let chunk = &bytes[i * 31..(i + 1) * 31];
        let mut padded = [0u8; 32];
        padded[1..].copy_from_slice(chunk);
        result.push(Felt::from_bytes_be(&padded));
    }

    let pending_word = if remaining_bytes > 0 {
        let remaining_chunk = &bytes[full_chunks * 31..];
        let mut padded = [0u8; 32];
        padded[32 - remaining_bytes..].copy_from_slice(remaining_chunk);
        Felt::from_bytes_be(&padded)
    } else {
        Felt::ZERO
    };

    result.push(pending_word);

    result.push(Felt::from(remaining_bytes as u64));

    result
}

pub fn extract_username_from_email(email: &str) -> String {
    email.split("@").next().unwrap_or(email).to_string()
}

pub fn validate_email_format(email: &str) -> Result<(), String> {
    if email.is_empty() || !email.contains("@") {
        return Err("Invalid email format".to_string());
    }

    Ok(())
}

pub fn validate_username_length(username: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 31 {
        return Err("Username must not be greater than 31 character".to_string());
    }

    Ok(())
}

pub fn validate_payment_inputs(
    reference: &str,
    user_id: &str,
    amount: &str,
) -> Result<Felt, String> {
    if reference.is_empty() {
        return Err("Reference cannot be empty".to_string());
    }

    if user_id.is_empty() {
        return Err("User ID cannot be empty".to_string());
    }

    let amount_felt = if amount.starts_with("0x") {
        Felt::from_hex(amount).map_err(|_| "Invalid hex amount".to_string())?
    } else {
        Felt::from_dec_str(amount).map_err(|_| "Invalid decimal amount format".to_string())?
    };

    Ok(amount_felt)
}

pub async fn check_strk_balance(
    provider: CartridgeJsonRpcProvider,
    address: Felt,
) -> Result<Felt, Box<dyn std::error::Error>> {
    let strk_address = felt!("0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d");

    match provider
        .call(
            FunctionCall {
                contract_address: strk_address,
                entry_point_selector: selector!("balance_of"),
                calldata: vec![address],
            },
            BlockId::Tag(BlockTag::Latest),
        )
        .await
    {
        Ok(balance_result) => {
            let balance = balance_result[0];
            if balance == Felt::ZERO {
                return Err(format!(
                    "Account {} has zero STRK balance. Please fund.",
                    format!("{:#x}", address)
                )
                .into());
            }

            println!("STRK balance: {}", balance);
            Ok(balance)
        }
        Err(e) => {
            println!("Failed to check STRK balance: {:?}", e);
            Err(Box::new(e))
        }
    }
}

pub async fn check_token_balance(
    token: Felt,
    user_address: Felt,
) -> Result<Felt, Box<dyn std::error::Error>> {
    let starknet_rpc_url = env::var("STARKNET_RPC_URL")?;
    let provider = create_provider_from_url(&starknet_rpc_url)?;

    match provider
        .call(
            FunctionCall {
                contract_address: token,
                entry_point_selector: selector!("balance_of"),
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
            println!("Token balance: {}", balance);
            Ok(balance)
        }
        Err(e) => {
            println!("Failed to check token balance: {:?}", e);
            Err(format!("Failed to check balance: {:?}", e).into())
        }
    }
}

pub async fn check_account_deployment_status(
    provider: &CartridgeJsonRpcProvider,
    address: Felt,
) -> bool {
    match provider
        .get_nonce(BlockId::Tag(BlockTag::Latest), address)
        .await
    {
        Ok(_) => {
            println!("Account at {:#x} is deployed", address);
            true
        }
        Err(_) => {
            println!("Account at {:#x} is not deployed", address);
            false
        }
    }
}

pub fn serialize_u256_type(amount_felt: Felt) -> (Felt, Felt) {
    let amount_bytes = amount_felt.to_bytes_be();
    let amount_low = Felt::from_bytes_be_slice(&amount_bytes[16..32]);
    let amount_high = Felt::from_bytes_be_slice(&amount_bytes[0..16]);
    (amount_low, amount_high)
}

pub fn build_approve_call(token: Felt, spender: Felt, amount_low: Felt, amount_high: Felt) -> Call {
    Call {
        to: token,
        selector: selector!("approve"),
        calldata: vec![spender, amount_low, amount_high],
    }
}

pub fn build_payment_calldata(
    token: Felt,
    amount_low: Felt,
    amount_high: Felt,
    reference: &str,
    user_id: &str,
) -> Vec<Felt> {
    let mut calldata = Vec::new();

    calldata.push(token);
    calldata.push(amount_low);
    calldata.push(amount_high);

    let reference_bytearray = encode_bytearray(reference);
    calldata.extend(reference_bytearray);

    let user_bytearray = encode_bytearray(user_id);
    calldata.extend(user_bytearray);

    calldata
}

pub fn build_payment_call(contract_address: Felt, calldata: Vec<Felt>) -> Call {
    Call {
        to: contract_address,
        selector: selector!("receive_payment"),
        calldata,
    }
}

pub fn create_provider_from_url(
    rpc_url: &str,
) -> Result<CartridgeJsonRpcProvider, Box<dyn std::error::Error>> {
    let url = Url::parse(rpc_url).map_err(|_| "Invalid RPC URL")?;
    Ok(CartridgeJsonRpcProvider::new(url))
}

pub fn parse_felt_from_hex(hex_str: &str) -> Result<Felt, Box<dyn std::error::Error>> {
    Felt::from_hex(hex_str).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

pub fn format_transaction_hash(hash: Felt) -> String {
    format!("{:#x}", hash)
}

pub async fn estimate_transaction_gas(
    controller: &Controller,
    calls: Vec<Call>,
) -> Result<(), String> {
    match controller.estimate_invoke_fee(calls).await {
        Ok(fee_estimate) => {
            println!("Gas estimation successful: {:?}", fee_estimate);
            Ok(())
        }
        Err(e) => {
            let detailed_error = get_detailed_error(&e).await;
            println!("Gas estimation failed: {}", detailed_error);
            Err(format!("Gas estimation failed: {}", detailed_error))
        }
    }
}

pub async fn execute_transaction_with_receipt(
    controller: &Controller,
    calls: Vec<Call>,
) -> Result<TransactionResponse, Box<dyn std::error::Error>> {
    match controller.execute_v3(calls).send().await {
        Ok(result) => {
            println!(
                "Transaction sent successfully: {:#x}",
                result.transaction_hash
            );

            let max_wait_time = Duration::from_secs(30);
            let poll_interval = Duration::from_secs(2);

            let receipt_result = poll_for_receipt(
                controller.provider(),
                result.transaction_hash,
                max_wait_time,
                poll_interval,
            )
            .await;

            match receipt_result {
                Ok(receipt) => {
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
                                    ("failed", revert_reason)
                                }
                            }
                        }
                        _ => ("success", "Transaction completed"),
                    };

                    Ok(TransactionResponse {
                        transaction_hash: format_transaction_hash(result.transaction_hash),
                        status: status.to_string(),
                        function_called: "receive_payment".to_string(),
                        message: Some(status_message.to_string()),
                    })
                }
                Err(e) => {
                    // If polling times out or fails, return pending status
                    eprintln!("Receipt polling failed or timed out: {}", e);
                    Ok(TransactionResponse {
                        transaction_hash: format_transaction_hash(result.transaction_hash),
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

async fn poll_for_receipt<P>(
    provider: &P,
    tx_hash: Felt,
    max_wait_time: Duration,
    poll_interval: Duration,
) -> Result<TransactionReceiptWithBlockInfo, Box<dyn std::error::Error>>
where
    P: Provider,
{
    let start_time = Instant::now();

    loop {
        if start_time.elapsed() >= max_wait_time {
            return Err("Transaction confirmation timeout".into());
        }

        match provider.get_transaction_receipt(tx_hash).await {
            Ok(receipt) => return Ok(receipt),
            Err(_) => {
                // Transaction not yet confirmed, wait before next poll
                sleep(poll_interval);
            }
        }
    }
}

pub fn create_failed_response(selector: &str, message: &str) -> TransactionResponse {
    TransactionResponse {
        transaction_hash: "0x0".to_string(),
        status: "failed".to_string(),
        function_called: selector.to_string(),
        message: Some(message.to_string()),
    }
}

pub async fn get_or_create_controller_from_db(
    database: &Database,
    controller_service: &ControllerService,
    user_id: &str,
    user_permissions: &[String],
) -> Result<(Controller, String, SessionOptions), Box<dyn std::error::Error>> {
    // check if controller details exist
    let controller_details = match database.get_controller_details(user_id) {
        Ok(Some(detail)) => detail,
        Ok(None) => {
            return Err("No controller found - need to create new controller".into());
        }
        Err(e) => {
            log::error!("Failed to get controller details: {:?}", e);
            return Err("Failed to get controller details".into());
        }
    };

    let current_time = Utc::now().timestamp();
    if controller_details.session_expires_at as i64 <= current_time {
        return Err("Controller session has expired".into());
    }

    // Recreate controller from stored info
    let controller =
        recreate_controller_from_info(controller_service, &controller_details, user_permissions)
            .await?;

    let response_session_policies = controller_service
        .generate_session_policies(user_permissions)
        .await;

    let session_options = SessionOptions {
        policies: response_session_policies,
        expires_at: controller_details.session_expires_at as u64,
    };

    Ok((controller, controller_details.username, session_options))
}

async fn recreate_controller_from_info(
    controller_service: &ControllerService,
    details: &ControllerSessionInfo,
    current_user_permissions: &[String],
) -> Result<Controller, Box<dyn std::error::Error>> {
    let starknet_rpc_url = env::var("STARKNET_RPC_URL")?;
    let app_id = env::var("APP_ID")?;

    let rpc_url = Url::parse(&starknet_rpc_url)?;
    let controller_address = Felt::from_hex(&details.controller_address)?;
    let owner = controller_service.create_owner_from_private_key()?;

    let mut controller = Controller::new(
        app_id.clone(),
        details.username.clone(),
        DEFAULT_CONTROLLER.hash,
        rpc_url,
        owner,
        controller_address,
        CHAIN_ID.clone(),
    );

    let stored_policies = &details.session_policies.0;

    log::debug!(
        "Using stored policies for session lookup: {:?}",
        stored_policies
    );
    log::debug!("Stored user permissions: {:?}", details.user_permissions);
    log::debug!("Current user permissions: {:?}", current_user_permissions);

    if details.user_permissions != current_user_permissions {
        log::warn!("User permissions have changed since session creation");
        return Err("User permissions have changed, need new session".into());
    }

    // Session is valid (timestamp already checked), create session with stored policies
    log::info!("Creating session with stored policies and expiration time");

    controller
        .create_session(stored_policies.clone(), details.session_expires_at as u64)
        .await?;

    log::info!("Successfully restored session for controller");

    Ok(controller)
}

pub async fn store_controller_in_db(
    controller_service: &ControllerService,
    database: &Database,
    user_id: &str,
    username: &str,
    controller: &Controller,
    session_options: &SessionOptions,
    user_permissions: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Storing controller session for user: {}", user_id);

    // Generate the actual policies that were used for the session
    let contract_address = parse_felt_from_hex(&session_options.policies.contract)?;
    let actual_policies =
        controller_service.build_session_policies(user_permissions, contract_address);

    let controller_details = ControllerSessionInfo {
        user_id: user_id.to_string(),
        username: username.to_string(),
        controller_address: format!("{:#x}", controller.address),
        session_policies: PolicyList(actual_policies), // Store the actual Vec<Policy> used
        session_expires_at: session_options.expires_at as i64,
        user_permissions: user_permissions.to_vec(),
        created_at: Utc::now(),
        last_used_at: Utc::now(),
        is_deployed: true,
    };

    match database.update_wallet_controller_info(user_id, &controller_details) {
        Ok(_) => {
            log::info!("Controller session stored for user: {}", user_id);
        }
        Err(e) => {
            log::error!("Failed to store controller session: {:?}", e);
            return Err("Failed to store controller session".into());
        }
    }

    Ok(())
}

pub async fn get_controller(
    database: &Database,
    controller_service: &ControllerService,
    user_id: &str,
    user_email: &str,
) -> Result<(Controller, ControllerSessionInfo), Box<dyn std::error::Error>> {
    let (user, user_permissions) =
        controller_service.validate_user_and_get_permissions(user_email)?;

    let (controller, username, session_options) = match get_or_create_controller_from_db(
        &database,
        &controller_service,
        &user.id,
        &user_permissions,
    )
    .await
    {
        Ok((controller, username, session_options)) => (controller, username, session_options),
        Err(_) => controller_service.create_controller(user_email).await?,
    };

    // Generate the actual policies for storage
    let contract_address = parse_felt_from_hex(&session_options.policies.contract)?;
    let build_policies =
        controller_service.build_session_policies(&user_permissions, contract_address);

    let details = ControllerSessionInfo {
        user_id: user_id.to_string(),
        username,
        controller_address: format!("{:#x}", controller.address),
        session_policies: PolicyList(build_policies.clone()),
        session_expires_at: session_options.expires_at as i64,
        user_permissions: user_permissions.to_vec(),
        created_at: Utc::now(),
        last_used_at: Utc::now(),
        is_deployed: true,
    };

    Ok((controller, details))
}
