use chrono::{Datelike, Utc};
use handlebars::Handlebars;
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use serde_json::json;
use std::env;
use std::error::Error;

use crate::integrations::model::TransactionDetails;

pub async fn send_verification_email(to_email: &str, otp: i32) -> Result<(), Box<dyn Error>> {
    let template_path = "src/service/templates/request_otp.hbs";
    let from_email = env::var("EMAIL_FROM")?;
    let smtp_username = env::var("SMTP_USERNAME")?;
    let smtp_password = env::var("SMTP_PASSWORD")?;

    let mut handlebars = Handlebars::new();
    handlebars.register_template_file("Verify OTP", template_path)?;

    let data = json!({
        "otp": otp
    });

    let html_body = handlebars.render("Verify OTP", &data)?;

    let email = Message::builder()
        .from(format!("Kharon Pay <{}>", from_email).parse::<Mailbox>()?)
        .to(to_email.parse::<Mailbox>()?)
        .subject("Verify your Kharon Pay account")
        .header(ContentType::TEXT_HTML)
        .body(html_body)?;

    let creds = Credentials::new(smtp_username, smtp_password);

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}

pub async fn send_confirmation_email(
    to_email: &str,
    details: TransactionDetails,
) -> Result<(), Box<dyn Error>> {
    let template_path = "src/service/templates/confirmation.hbs";
    let from_email = env::var("EMAIL_FROM")?;
    let smtp_username = env::var("SMTP_USERNAME")?;
    let smtp_password = env::var("SMTP_PASSWORD")?;

    let mut handlebars = Handlebars::new();
    handlebars.register_template_file("Disbursement Confirmation", template_path)?;

    let current_year = Utc::now().year();

    let data = json!({
        "reference": details.reference,
        "transaction_ref": details.transaction_ref,
        "crypto_amount": details.crypto_amount,
        "crypto_symbol": details.crypto_symbol,
        "fiat_amount": details.fiat_amount,
        "bank_name": details.bank_name,
        "account_number": details.account_number,
        "account_name": details.account_name,
        "transaction_hash": details.transaction_hash,
        "transaction_date": details.transaction_date,
        "current_year": current_year
    });

    let html_body = handlebars.render("Disbursement Confirmation", &data)?;

    let email = Message::builder()
        .from(format!("Kharon Pay <{}>", from_email).parse::<Mailbox>()?)
        .to(to_email.parse::<Mailbox>()?)
        .subject("Withdrawal Confirmation - Kharon Pay")
        .header(ContentType::TEXT_HTML)
        .body(html_body)?;

    let creds = Credentials::new(smtp_username, smtp_password);

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}

pub async fn send_admin_failed_transfer_alert(
    details: &TransactionDetails,
) -> Result<(), Box<dyn Error>> {
    let template_path = "src/service/templates/failed_transfer.hbs";
    let from_email = env::var("EMAIL_FROM")?;
    let smtp_username = env::var("SMTP_USERNAME")?;
    let smtp_password = env::var("SMTP_PASSWORD")?;

    // Get admin emails from environment variable (comma-separated)
    let admin_emails_str =
        env::var("ADMIN_EMAILS").unwrap_or_else(|_| "evans@kharonlabs.com".to_string());
    let admin_emails: Vec<&str> = admin_emails_str.split(',').map(|s| s.trim()).collect();

    let mut handlebars = Handlebars::new();
    handlebars.register_template_file("Admin Failed Transfer Alert", template_path)?;

    let current_year = Utc::now().year();

    let data = json!({
        "reference": details.reference,
        "transaction_ref": details.transaction_ref,
        "crypto_amount": details.crypto_amount,
        "crypto_symbol": details.crypto_symbol,
        "fiat_amount": details.fiat_amount,
        "bank_name": details.bank_name,
        "account_number": details.account_number,
        "account_name": details.account_name,
        "transaction_hash": details.transaction_hash,
        "transaction_date": details.transaction_date,
        "current_year": current_year
    });

    let html_body = handlebars.render("Admin Failed Transfer Alert", &data)?;

    let creds = Credentials::new(smtp_username, smtp_password);
    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    // Send to all admin emails
    for admin_email in admin_emails {
        if admin_email.is_empty() {
            continue;
        }

        let email = Message::builder()
            .from(format!("Kharon Pay Alerts <{}>", from_email).parse::<Mailbox>()?)
            .to(admin_email.parse::<Mailbox>()?)
            .subject("🚨 URGENT: Transfer Failure Alert - Immediate Action Required")
            .header(ContentType::TEXT_HTML)
            .body(html_body.clone())?;

        match mailer.send(&email) {
            Ok(_) => {
                log::info!("Failed transfer alert sent to admin: {}", admin_email);
            }
            Err(e) => {
                log::error!("Failed to send alert to admin {}: {}", admin_email, e);
            }
        }
    }

    Ok(())
}

pub async fn send_request_password_reset_email(
    to_email: &str,
    link: &str,
) -> Result<(), Box<dyn Error>> {
    let template_path = "service/templates/request_password_reset.hbs";
    let from_email = env::var("EMAIL_FROM")?;
    let smtp_username = env::var("SMTP_USERNAME")?;
    let smtp_password = env::var("SMTP_PASSWORD")?;

    let mut handlebars = Handlebars::new();
    handlebars.register_template_file("Reset Password Token", template_path)?;

    let data = json!({
        "link": link
    });

    let html_body = handlebars.render("Reset Password Token", &data)?;

    let email = Message::builder()
        .from(format!("Kharon Pay <{}>", from_email).parse::<Mailbox>()?)
        .to(to_email.parse::<Mailbox>()?)
        .subject("Password Reset Link")
        .header(ContentType::TEXT_HTML)
        .body(html_body)?;

    let creds = Credentials::new(smtp_username, smtp_password);

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}

pub async fn send_password_reset_email(to_email: &str) -> Result<(), Box<dyn Error>> {
    let template_path = "./templates/reset_password.hbs";
    let from_email = env::var("EMAIL_FROM")?;
    let smtp_username = env::var("SMTP_USERNAME")?;
    let smtp_password = env::var("SMTP_PASSWORD")?;

    let mut handlebars = Handlebars::new();
    handlebars.register_template_file("Password Reset", template_path)?;

    let html_body = handlebars.render("Password Reset", &json!({}))?;

    let email = Message::builder()
        .from(format!("Kharon Pay <{}>", from_email).parse::<Mailbox>()?)
        .to(to_email.parse::<Mailbox>()?)
        .subject("Password Reset Successful")
        .header(ContentType::TEXT_HTML)
        .body(html_body)?;

    let creds = Credentials::new(smtp_username, smtp_password);

    let mailer = SmtpTransport::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(&email)?;

    Ok(())
}
