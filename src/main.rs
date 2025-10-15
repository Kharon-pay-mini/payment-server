mod auth;
mod config;
mod database;
mod helpers;
mod integrations;
mod models;
mod pricefeed;
mod routes;
mod service;
mod wallets;

use std::sync::{Arc, Mutex};

use actix_cors::Cors;
use actix_web::{
    http::header,
    middleware::{from_fn, Logger},
    web, App, HttpServer,
};
use config::{
    config::Config,
    config_scope,
    redis_config::{init_redis_pool, RedisPool},
};
use database::db::Database;
use dotenv::dotenv;
use pricefeed::pricefeed::PriceData;
use service::geolocation::geolocator::GeoLocator;

// use crate::helpers::payment_helpers::start_retry_processor;

pub struct AppState {
    db: Database,
    env: Config,
    pub redis_pool: RedisPool,
    pub geo_locator: GeoLocator,
    pub price_feed: Arc<Mutex<PriceData>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    log::info!("Starting Server......");
    println!("Initializing environment variables...");
    dotenv().ok();

    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "debug, sqlx=warn, actix_web=info, diesel=info");
    }

    env_logger::init();

    let config = Config::init();

    let db = match database::db::Database::new() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to initialize DB: {:?}", e);
            std::process::exit(1);
        }
    };

    let redis_pool = init_redis_pool(&config.redis_url)
        .await
        .expect("Failed to create Redis pool");

    let price_data = pricefeed::pricefeed::init_price_feed().await;

    let geo_locator = GeoLocator::new(config.ip_info_token.clone());
    let port = config.port.parse().expect("PORT must be i16 type");

    let app_state = web::Data::new(AppState {
        db: db.clone(),
        env: config.clone(),
        redis_pool: redis_pool.clone(),
        geo_locator: geo_locator.clone(),
        price_feed: price_data.clone(),
    });
    // start_retry_processor(app_state.clone()).await;

    log::info!("Server started successfully...");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_origin("https://api.flutterwave.com")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
                header::HeaderName::from_static("x-requested-with"),
            ])
            .supports_credentials();

        App::new()
            .app_data(app_state.clone())
            .configure(config_scope::config)
            .wrap(cors)
            .wrap(Logger::default())
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
