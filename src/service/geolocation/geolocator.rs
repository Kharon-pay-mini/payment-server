use awc::Client;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct IpInfoResponse {
    pub city: Option<String>,
    pub country: Option<String>,
}

#[derive(Clone)]
pub struct GeoLocator {
    token: String,
}

impl GeoLocator {
    pub fn new(token: String) -> Self {
        Self { token }
    }

    pub async fn lookup(&self, ip: &str) -> Result<IpInfoResponse, Box<dyn std::error::Error>> {
        let url = format!("https://ipinfo.io/{ip}?token={}", self.token);
        let client = Client::default();

        let mut response = client.get(url).send().await?;
        let body = response.body().limit(65536).await?;

        let geo: IpInfoResponse = serde_json::from_slice(&body)?;
        Ok(geo)
    }
}
