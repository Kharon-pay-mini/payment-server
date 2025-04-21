use bb8::Pool;
use bb8_redis::RedisConnectionManager;
use redis::RedisError;

pub type RedisPool = Pool<RedisConnectionManager>;

pub async fn init_redis_pool(redis_url: &str) -> Result<RedisPool, RedisError> {
    let manager = RedisConnectionManager::new(redis_url)?;
    Pool::builder().max_size(15).build(manager).await
}
