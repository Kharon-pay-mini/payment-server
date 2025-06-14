use crate::helpers::models::AuthHeaders;
use actix_web::{web::Bytes, HttpRequest};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn extract_auth_headers(req: &HttpRequest) -> Result<AuthHeaders, String> {
    let api_key = req
        .headers()
        .get("X-Api-Key")
        .and_then(|v| v.to_str().ok())
        .ok_or("Missing X-Api-Key header")?;

    let timestamp = req
        .headers()
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or("Missing X-Timestamp header")?;

    let signature = req
        .headers()
        .get("X-Signature")
        .and_then(|v| v.to_str().ok())
        .ok_or("Missing X-Signature header")?;

    Ok(AuthHeaders {
        api_key: api_key.to_string(),
        timestamp: timestamp.to_string(),
        signature: signature.to_string(),
    })
}

pub fn verify_api_key(provided_key: &str, expected_key: &str) -> Result<(), String> {
    if provided_key != expected_key {
        return Err("Invalid API Key".to_string());
    }
    Ok(())
}

pub fn verify_hmac_signature(
    timestamp: &str,
    body: &Bytes,
    provided_signature: &str,
    hmac_secret: &str,
) -> Result<(), String> {
    let payload = String::from_utf8_lossy(body);
    let message = format!("{}{}", timestamp, payload);

    let mut mac =
        Hmac::<Sha256>::new_from_slice(hmac_secret.as_bytes()).map_err(|_| "Invalid HMAC key")?;
    mac.update(message.as_bytes());
    let calculated_signature = hex::encode(mac.finalize().into_bytes());

    if calculated_signature != provided_signature {
        return Err("HMAC Signature invalid.".to_string());
    }

    Ok(())
}
