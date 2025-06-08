use anyhow::{anyhow, Ok, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::time::{self, Duration};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PriceData {
    pub price: f64,
    pub timestamp: i64,
    pub sources: Vec<SourcePrice>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SourcePrice {
    pub source: String,
    pub price: f64,
}

impl Default for PriceData {
    fn default() -> Self {
        PriceData {
            price: 0.0,
            timestamp: chrono::Utc::now().timestamp(),
            sources: Vec::new(),
        }
    }
}

// async fn get_binance_price() -> Result<f64> {
//     let client = Client::new();
//     let response = client
//         .get("https://api.binance.com/api/v3/ticker/price?symbol=USDTNGN")
//         .send()
//         .await?;

//     if response.status().is_success() {
//         let data: serde_json::Value = response.json().await?;
//         let price = data["price"]
//             .as_str()
//             .ok_or_else(|| anyhow!("Binance: invalid price format"))?
//             .parse::<f64>()?;
//         Ok(price)
//     } else {
//         Err(anyhow!("Binance API error: {}", response.status()))
//     }
// }

async fn get_cryptocompare_price() -> Result<f64> {
    let client = Client::new();
    let response = client
        .get("https://min-api.cryptocompare.com/data/price?fsym=USDT&tsyms=NGN")
        .send()
        .await?;

    if response.status().is_success() {
        let data: serde_json::Value = response.json().await?;
        let price = data["NGN"]
            .as_f64()
            .ok_or_else(|| anyhow!("Cryptocompare: Invalid price format"))?;
        Ok(price)
    } else {
        Err(anyhow!("Cryptocompare API error: {}", response.status()))
    }
}

// async fn get_quidax_price() -> Result<f64> {
//     let client = Client::new();
//     let response = client
//         .get("https://www.quidax.com/api/v1/markets/usdtngn/ticker")
//         .send()
//         .await?;

//     println!("Quidax Response: {:?}", response);

//     if response.status().is_success() {
//         let data: serde_json::Value = response.json().await?;
//         let price = data["ticker"]["last"]
//             .as_str()
//             .and_then(|s| s.parse::<f64>().ok())
//             .ok_or_else(|| anyhow!("Quidax: Invalid price format"))?;
//         Ok(price)
//     } else {
//         Err(anyhow!("Quidax API error: {}", response.status()))
//     }
// }

pub async fn update_price_data(price_data: Arc<Mutex<PriceData>>) {
    let mut sources = Vec::new();
    let mut sum = 0.0;
    let mut count = 0;

    // match get_binance_price().await {
    //     std::result::Result::Ok(price) => {
    //         sources.push(SourcePrice {
    //             source: "Binance".to_string(),
    //             price,
    //         });
    //         sum += price;
    //         count += 1;
    //         println!("Binance price: {}", price);
    //     }
    //     Err(e) => {
    //         log::error!("Error fetching Binance price: {}", e);
    //     }
    // }

    match get_cryptocompare_price().await {
        std::result::Result::Ok(price) => {
            sources.push(SourcePrice {
                source: "Cryptocompare".to_string(),
                price,
            });
            sum += price;
            count += 1;
            println!("Cryptocompare price: {}", price);
        }
        Err(e) => {
            log::error!("Error fetching Cryptocompare price: {}", e);
        }
    }

    // match get_quidax_price().await {
    //     std::result::Result::Ok(price) => {
    //         sources.push(SourcePrice {
    //             source: "Luno".to_string(),
    //             price,
    //         });
    //         sum += price;
    //         count += 1;
    //         println!("Luno price: {}", price);
    //     }
    //     Err(e) => {
    //         log::error!("Error fetching Luno price: {}", e);
    //     }
    // }

    if count > 0 {
        let average_price = sum / count as f64;
        let mut data = price_data.lock().unwrap();
        *data = PriceData {
            price: average_price,
            timestamp: chrono::Utc::now().timestamp(),
            sources,
        };
        log::info!(
            "Price updated: {} NGN per USDT (from {} sources)",
            average_price,
            count
        )
    } else {
        log::error!("Failed to fetch price data from any source");
    }
}

pub async fn init_price_feed() -> Arc<Mutex<PriceData>> {
    let price_data = Arc::new(Mutex::new(PriceData::default()));

    update_price_data(price_data.clone()).await;

    let price_data_clone = price_data.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(1200));
        loop {
            interval.tick().await;
            update_price_data(price_data_clone.clone()).await;
        }
    });

    log::info!("USDT-NGN price feed initialized and updating every 5 seconds");
    price_data
}

pub fn get_current_usdt_ngn_rate(price_data: Arc<Mutex<PriceData>>) -> Result<f64> {
    let data = price_data
        .lock()
        .map_err(|_| anyhow!("Failed to acquire price data lock"))?;

    if data.price <= 0.0 {
        return Err(anyhow!("No valid price data available"));
    }

    Ok(data.price)
}
