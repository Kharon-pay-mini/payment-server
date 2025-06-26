use starknet::core::types::Felt;

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
            Felt::ZERO, // data.len()
            Felt::from_bytes_be(&padded), //pending word
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

/* 

pub fn encode_string_to_felt_array(input: &str) -> Vec<Felt> {
    let bytes = input.as_bytes();
    let mut result = Vec::new();

    result.push(Felt::from(bytes.len() as u64));

    for chunk in bytes.chunks(31) {
        let mut padded = [0u8; 32];
        padded[32 - chunk.len()..].copy_from_slice(chunk);
        result.push(Felt::from_bytes_be(&padded));
    }

    result
}

pub fn encode_short_string(input: &str) -> Result<Felt, &'static str> {
    if input.len() > 31 {
        return Err("String too long for short string encoding");
    }

    let bytes = input.as_bytes();
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    Ok(Felt::from_bytes_be(&padded))
}

pub fn encode_string(input: &str) -> Vec<Felt> {
    if input.len() <= 31 {
        vec![encode_short_string(input).unwrap()]
    } else {
        encode_string_to_felt_array(input)
    }
}

*/