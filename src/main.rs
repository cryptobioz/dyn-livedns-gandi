#[macro_use]
extern crate serde_derive;
extern crate reqwest;

#[derive(Deserialize, Debug)]
struct Ipinfo {
    ip: String,
}

fn main() {
    let ip = match get_public_ip() {
        Ok(v) => v,
        Err(e) => {
            println!("Error: {:?}", e);
            return
        }
    };

    println!("{:?}", ip);
}

fn get_public_ip() -> Result<String, reqwest::Error> {
    let client = reqwest::Client::new();

    let ipinfo: Ipinfo = client
        .get("https://ipinfo.io")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
        .send()?.json()?;

    Ok(ipinfo.ip)
}
