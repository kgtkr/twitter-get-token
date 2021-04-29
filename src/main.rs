use crypto::mac::Mac;
use serde_derive::Deserialize;

use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
struct Config {
    ck: String,
    cs: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OAuthToken {
    oauth_token: String,
    oauth_token_secret: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = toml::from_str::<Config>(&std::fs::read_to_string("config.toml")?)?;
    println!("screen name:");
    let sn = {
        let mut sn = String::new();
        std::io::stdin().read_line(&mut sn)?;
        sn.trim().to_string()
    };
    println!("password:");
    let pw = rpassword::read_password()?;
    let (tk, ts) = token(&config.ck, &config.cs, &sn, &pw).await?;

    println!("# {}", sn);
    println!("tk=\"{}\"", tk);
    println!("ts=\"{}\"", ts);
    Ok(())
}

async fn token(
    ck: &str,
    cs: &str,
    sn: &str,
    pw: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let url = "https://api.twitter.com/oauth/access_token";

    let params = [
        ("x_auth_mode", "client_auth"),
        ("x_auth_password", pw),
        ("x_auth_username", sn),
    ];

    let oauth = [
        ("oauth_consumer_key", ck),
        ("oauth_nonce", &Uuid::new_v4().to_string()),
        ("oauth_signature_method", "HMAC-SHA1"),
        (
            "oauth_timestamp",
            &chrono::Utc::now().timestamp().to_string(),
        ),
        ("oauth_token", ""),
        ("oauth_version", "1.0a"),
    ];

    let key = vec![url_encode(cs), "".to_string()];

    let base = &{
        let mut v = vec![];
        v.extend_from_slice(&oauth);
        v.extend_from_slice(&params);
        v
    }[..];

    let base_str = &base
        .iter()
        .map(|&(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&");

    let encode_arr = vec!["POST".to_string(), url_encode(url), url_encode(base_str)];

    let mut hmac = crypto::hmac::Hmac::new(crypto::sha1::Sha1::new(), key.join("&").as_bytes());
    hmac.input(encode_arr.join("&").as_bytes());
    let oauth_signature = base64::encode(&hmac.result().code());

    let items = {
        let mut v = vec![];
        v.extend_from_slice(&oauth);
        v.extend_from_slice(&[("oauth_signature", &oauth_signature)]);
        v.iter()
            .map(|&(k, v)| format!(r#"{}="{}""#, k, url_encode(v)))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let client = reqwest::Client::new();

    let res = client
        .post(url)
        .header(hyper::header::AUTHORIZATION, format!("OAuth {}", items))
        .form(&params)
        .send()
        .await?;

    let text = res.text().await?;

    let result = serde_urlencoded::from_str::<OAuthToken>(&text)?;

    Ok((result.oauth_token, result.oauth_token_secret))
}

fn url_encode(url: &str) -> String {
    utf8_percent_encode(url, NON_ALPHANUMERIC).to_string()
}
