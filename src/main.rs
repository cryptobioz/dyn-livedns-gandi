#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;

extern crate reqwest;
extern crate ini;
use ini::Ini;

#[derive(Deserialize, Debug)]
struct Ipinfo {
    ip: String,
}

#[derive(Deserialize, Serialize)]
struct Record {
    rrset_values: Vec<String>,
}


struct Config {
    api_key: String,
    records: Vec<String>,
}


fn load_config() -> Config {
    let conf = Ini::load_from_file("config.ini").unwrap();

    let section = conf.section(Some("main".to_owned())).unwrap();
    let api_key = section.get("api_key").unwrap();

    return Config{
        api_key: api_key.to_owned(),
        records: Vec::new(),
    }
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

fn main() {

    let config = load_config();

    let ip = match get_public_ip() {
        Ok(v) => v,
        Err(e) => {
            println!("Error: {:?}", e);
            return
        }
    };

    let record = Record{
        rrset_values: vec![ip],
    };


    let client = reqwest::Client::new();

    let response = client
        .put("https://dns.api.gandi.net/api/v5/zones/XXXXXXXXXXXXXXXX/records/foo/A")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Api-Key", config.api_key)
        .body(serde_json::to_string(&record).unwrap())
        .send().unwrap();

    if response.status().is_success() {
        println!("Record updated!");
    } else {
        println!("Record updated failed.")
    }
}
