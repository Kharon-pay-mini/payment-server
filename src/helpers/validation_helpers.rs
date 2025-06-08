use uuid::Uuid;

pub fn validate_user_id(user_id_str: &str) -> Result<Uuid, String> {
    let user_id = Uuid::parse_str(user_id_str).map_err(|_| "Invalid user ID format")?;

    if user_id.to_string().len() > 40 {
        return Err("User ID too long".to_string());
    }

    Ok(user_id)
}

pub fn validate_reference(reference: &str) -> Result<(), String> {
    if reference.len() > 56 {
        return Err("Reference too long".to_string());
    }

    Ok(())
}

pub fn validate_amount_match(request_amount: &str, pending_amount: i64) -> Result<i64, String> {
    let amount: i64 = request_amount
        .parse()
        .map_err(|_| "Invalid amount format")?;

    if amount != pending_amount {
        return Err(format!(
            "Amount mismatch: expected {}, got {}",
            pending_amount, amount
        ));
    }

    Ok(amount)
}

pub fn verify_timestamp(timestamp_str: &str) -> Result<(), String> {
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let request_timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| "Invalid timestamp format")?;

    if current_timestamp.abs_diff(request_timestamp) > 300 {
        return Err("Timestamp outside acceptable window".to_string());
    }

    Ok(())
}
