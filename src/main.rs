#[macro_use]
extern crate clap;
use clap::{App, Arg};
mod api;
fn main() {
    let app = App::new("get-twitter-token")
        .version("0.1.0")
        .author("tkr <kgtkr.jp@gmail.com>")
        .about("Twitterのトークン取得")
        .arg(
            Arg::with_name("consumer_key")
                .help("コンシューマーキー")
                .long("consumer-key")
                .visible_alias("ck")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("consumer_secret")
                .help("コンシューマーシークレット")
                .long("consumer-secret")
                .visible_alias("cs")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("screen_name")
                .help("スクリーンネーム")
                .long("screen-name")
                .short("s")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("password")
                .help("パスワード")
                .long("password")
                .short("p")
                .takes_value(true)
                .required(true),
        );

    let matches = app.get_matches();

    let ck = matches.value_of("consumer_key").unwrap();
    let cs = matches.value_of("consumer_secret").unwrap();
    let sn = matches.value_of("screen_name").unwrap();
    let pw = matches.value_of("password").unwrap();

    api::token(ck, cs, sn, pw);
}
