use crypto::mac::Mac;
use serde_derive::Deserialize;
use std::collections::HashMap;

use url::percent_encoding::utf8_percent_encode;
use url::percent_encoding::FORM_URLENCODED_ENCODE_SET;
use uuid::Uuid;

#[derive(Debug, Clone, Deserialize)]
struct Config {
    ck: String,
    cs: String,
}

fn main() -> Result<(), Box<std::error::Error>> {
    let config = toml::from_str::<Config>(&std::fs::read_to_string("config.toml")?)?;
    println!("screen name:");
    let mut sn = String::new();
    std::io::stdin().read_line(&mut sn)?;
    let sn = sn;
    println!("password:");
    let pw = rpassword::read_password()?;

    let (tk, ts) = token(&config.ck, &config.cs, &sn, &pw)?;
    println!("tk=\"{}\"", tk);
    println!("ts=\"{}\"", ts);

    Ok(())
}

fn token(
    ck: &str,
    cs: &str,
    sn: &str,
    pw: &str,
) -> Result<(String, String), Box<std::error::Error>> {
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
        .header(hyper::header::Authorization(format!("OAuth {}", items)))
        .form(&params)
        .send();

    let result = serde_urlencoded::from_str::<HashMap<String, String>>(&res?.text()?)?;

    Ok((
        result
            .get("oauth_token")
            .ok_or("oauth_token not exist")?
            .to_string(),
        result
            .get("oauth_token_secret")
            .ok_or("oauth_token_secret not exist")?
            .to_string(),
    ))
}

fn url_encode(url: &str) -> String {
    utf8_percent_encode(url, FORM_URLENCODED_ENCODE_SET)
}
