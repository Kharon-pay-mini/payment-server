mod auth;
mod config;
mod database;
mod integrations;
mod middleware;
mod models;
mod pricefeed;
mod routes;
mod service;

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
use diesel_migrations::{EmbeddedMigrations, MigrationHarness};
use dotenv::dotenv;
use middleware::security_log::security_logger_middleware;
use pricefeed::pricefeed::PriceData;
use service::geolocation::geolocator::GeoLocator;

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
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    dotenv().ok();
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

    println!("Server started successfully...");

    let geo_locator = GeoLocator::new(config.ip_info_token.clone());
    let port = config.port.parse().expect("PORT must be i16 type");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
            ]);
        // .supports_credentials()

        App::new()
            .app_data(web::Data::from(Arc::new(AppState {
                db: db.clone(),
                env: config.clone(),
                redis_pool: redis_pool.clone(),
                geo_locator: geo_locator.clone(),
                price_feed: price_data.clone(),
            })))
            .configure(config_scope::config)
            .wrap(cors)
            .wrap(Logger::default())
            .wrap(from_fn(security_logger_middleware))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
