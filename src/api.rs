extern crate base64;
extern crate chrono;
extern crate crypto;
extern crate hyper;
extern crate reqwest;
extern crate url;
extern crate uuid;
use std::collections::HashMap;
use self::crypto::mac::Mac;
use self::url::percent_encoding::utf8_percent_encode;
use self::url::percent_encoding::FORM_URLENCODED_ENCODE_SET;
use self::uuid::Uuid;
extern crate serde_urlencoded;

pub fn token(ck: &str, cs: &str, sn: &str, pw: &str) -> Option<(String, String)> {
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
  let result =
    serde_urlencoded::from_str::<HashMap<String, String>>(&res.unwrap().text().unwrap()).unwrap();

  Some((
    result.get("oauth_token").unwrap().to_string(),
    result.get("oauth_token_secret").unwrap().to_string(),
  ))
}

fn url_encode(url: &str) -> String {
  utf8_percent_encode(url, FORM_URLENCODED_ENCODE_SET)
}
