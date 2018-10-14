#[macro_use]
extern crate serde_derive;

#[cfg(test)]
extern crate tempdir;
#[cfg(test)]
extern crate mockito;

extern crate serde_json;
extern crate reqwest;
extern crate clap;
extern crate ini;
use ini::Ini;
use clap::{Arg, App};
use std::process::exit;



#[cfg(not(test))]
const GANDI_URL: &str = "https://dns.api.gandi.net";

#[cfg(test)]
const GANDI_URL: &str = mockito::SERVER_URL;



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
    domain: String,
    zone: String,
}

#[derive(Deserialize, Serialize)]
struct GandiZones {
    uuid: String,
    name: String,
}

fn load_config(config: &str) -> Result<Config, String> {
    let conf = match Ini::load_from_file(config) {
        Ok(v) => v,
        Err(e) => return Err(format!("failed to read config file: {}", e)),
    };

    let section = match conf.section(Some("main".to_owned())) {
        Some(v) => v,
        None => return Err("failed to read the section [main]".to_owned()),
    };

    let api_key = match section.get("api_key") {
        Some(v) => v.to_owned(),
        None => return Err("failed to retrieve the field `api_key`".to_owned()),
    };

    let records: Vec<String> = match section.get("records") {
        Some(v) => v.split(',').map(|s| s.to_string()).collect(),
        None => return Err("failed to retrieve the field `records`".to_owned()),
    };

    let domain = match section.get("domain") {
        Some(v) => v.to_owned(),
        None => String::new(),
    };

    let zone = match section.get("zone") {
        Some(v) => v.to_owned(),
        None => String::new(),
    };

    if zone.is_empty() && domain.is_empty() {
        return Err("a zone or a domain must be specified".to_owned());
    }

    Ok(Config{
        api_key,
        records,
        domain,
        zone,
    })
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

fn get_zone_from_domain(api_key: String, domain: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let mut response = match client
    .get(&format!("{}/api/v5/zones", GANDI_URL))
    .header(reqwest::header::CONTENT_TYPE, "application/json")
    .header("X-Api-Key", api_key)
    .send() {
        Ok(v) => v,
        Err(e) => return Err(format!("failed to retrieve zones: {:?}", e)),
    };

    let body = match response.text() {
        Ok(v) => v,
        Err(e) => return Err(format!("failed to read body: {:?}", e)),
    };

    if ! response.status().is_success() {
        let error: serde_json::Value = serde_json::from_str(&body).unwrap();
        return Err(format!("failed to get zone from domain: {} - {}", error["cause"], error["message"]));
    }


    let zones: Vec<GandiZones> = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => return Err(format!("failed to decode body: {:?}", e)),
    };

    for zone in zones {
        if zone.name == domain {
            return Ok(zone.uuid);
        }
    }

    Err(String::from("no zone matching provided domain"))
}

fn update_record(zone: &str, api_key: String, record: &str, ip: String) -> Result<(), String> {
    let r = Record{
        rrset_values: vec![ip],
    };
    let client = reqwest::Client::new();
    let mut response = match client
        .put(&format!("https://dns.api.gandi.net/api/v5/zones/{}/records/{}/A", zone, record))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Api-Key", api_key)
        .body(serde_json::to_string(&r).unwrap())
        .send() {
            Ok(v) => v,
            Err(e) => return Err(format!("failed to send update request: {:?}", e)),
    };

    if response.status().is_success() {
        Ok(())
    } else {
        let body = match response.text() {
            Ok(v) => v,
            Err(e) => return Err(format!("failed to read body: {:?}", e)),
        };

        let error: serde_json::Value = match serde_json::from_str(&body) {
            Ok(v) => v,
            Err(e) => return Err(format!("failed to decode body: {:?}", e)),
        };
        return Err(format!("failed to update record: {} - {}", error["cause"], error["message"]));
    }
}

fn main() {
    exit(run());
}

fn run() -> i32 {
    let matches = App::new("dyn-livedns-gandi")
        .version("0.0.1")
        .about("Update your Gandi LiveDNS records with your current IP address")
        .author("Léo Depriester")
        .arg(Arg::with_name("config")
             .short("c")
             .long("config")
             .value_name("FILE")
             .help("Sets a custom config file")
             .required(true)
             .takes_value(true))
        .get_matches();


    let config_file = match matches.value_of("config") {
        Some(v) => v,
        None => {
            println!("failed to retrieve the value of `config`");
            return 1;
        },
    };

    let mut config = match load_config(config_file) {
        Ok(v) => v,
        Err(e) => {
            println!("Error: {:?}", e);
            return 1;
        },
    };

    let ip = match get_public_ip() {
        Ok(v) => v,
        Err(e) => {
            println!("Error: {:?}", e);
            return 1;
        }
    };

    if config.zone.is_empty() {
        config.zone = match get_zone_from_domain(config.api_key.to_owned(), &config.domain) {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {:?}", e);
                return 1;
            },
        };
    }

    let mut exit_code = 0;

    for record in config.records {
        match update_record(&config.zone, config.api_key.to_owned(), &record, ip.to_owned()) {
            Ok(_) => println!("Record `{}` updated with value: {}", record, ip),
            Err(e) => {
                println!("Failed to update record `{}`: {}", record, e);
                exit_code = 2;
            },
        }
    }
    return exit_code;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::prelude::*;
    use std::fs;
    use tempdir::TempDir;
    use mockito::mock;


    #[test]
    fn load_config_no_api_key() {
        let dir = TempDir::new("dyn-livedns-gandi").unwrap();
        let file_path = dir.path().join("config.ini");
        let mut file = File::create(&file_path).unwrap();
        match file.write_all(b"\
        [main]\
        ") {
            Ok(_) => {},
            Err(e) => assert!(false, "failed to write fake config file: {}", e),
        };
        let file_path_str = file_path.to_str().unwrap();

        let result = load_config(file_path_str);

        match fs::remove_dir_all(dir) {
            Ok(_) => {},
            Err(e) => assert!(false, "failed to remove tmp dir: {}", e),
        };

        match result {
            Ok(_) => assert!(false, "api_key should be undefined"),
            Err(_) => assert!(true),
        };
    }

    #[test]
    fn load_config_no_main() {
        let dir = TempDir::new("dyn-livedns-gandi").unwrap();
        let file_path = dir.path().join("config.ini");
        let mut file = File::create(&file_path).unwrap();
        match file.write_all(b"\
        [foo]\
        api_key = bar\
        ") {
            Ok(_) => {},
            Err(e) => assert!(false, "failed to write fake config file: {}", e),
        };
        let file_path_str = file_path.to_str().unwrap();


        let result = load_config(file_path_str);


        match fs::remove_dir_all(dir) {
            Ok(_) => {},
            Err(e) => assert!(false, "failed to remove tmp dir: {}", e),
        };

        match result {
            Ok(_) => assert!(false, "main section should be undefined"),
            Err(_) => assert!(true),
        };
    }

    #[test]
    fn load_config_valid() {
        let dir = TempDir::new("dyn-livedns-gandi").unwrap();
        let file_path = dir.path().join("config.ini");
        let mut file = File::create(&file_path).unwrap();
        match file.write_all(b"\
        [main]\n
        api_key=foo\n
        records=alpha,beta\n
        domain = fake-domain.tld\n
        ") {
            Ok(_) => {},
            Err(e) => assert!(false, "failed to write fake config file: {}", e),
        };
        let file_path_str = file_path.to_str().unwrap();


        let config = load_config(file_path_str);


        match fs::remove_dir_all(dir) {
            Ok(_) => {},
            Err(e) => assert!(false, "failed to remove tmp dir: {}", e),
        };

        let result = match config {
            Ok(v) => v,
            Err(e) => return assert!(false, "failed to load config: {}", e),
        };

        // API Key
        assert_eq!("foo", result.api_key, "Expected foo, got {}", result.api_key);
        // Records
        assert_eq!(vec!["alpha", "beta"], result.records, "Expected [alpha, beta], got {:?}", result.records);
    }

    #[test]
    fn get_zone_from_domain_valid() {
        // Mocking
        let data = r#"[
            {
                "retry": 3600,
                "uuid": "ec48f571-3787-4083-9336-882c4e2de802",
                "zone_href": "https://dns.api.gandi.net/api/v5/zones/ec48f571-3787-4083-9336-882c4e2de802",
                "minimum": 10800,
                "domains_href": "https://dns.api.gandi.net/api/v5/zones/ec48f571-3787-4083-9336-882c4e2de802/domains",
                "refresh": 10800,
                "zone_records_href": "https://dns.api.gandi.net/api/v5/zones/ec48f571-3787-4083-9336-882c4e2de802/records",
                "expire": 604800,
                "sharing_id": "cb8232db-7123-40bb-b181-d49d4922c7b7",
                "serial": 153906193,
                "email": "hostmaster.gandi.net.",
                "primary_ns": "ns1.gandi.net",
                "name": "fake-domain.tld"
            }
        ]"#;
        let _m = mock("GET", "/api/v5/zones")
            .with_status(200)
            .with_header("Content-Type", "application/json")
            .with_body(data)
            .create();


        let domain = String::from("fake-domain.tld");
        let api_key = String::from("f4keAp1K3y");

        let zone = get_zone_from_domain(api_key, &domain);

        let result = match zone {
            Ok(v) => v,
            Err(e) => return assert!(true, "{}", e),
        };

        assert_eq!("ec48f571-3787-4083-9336-882c4e2de802", result, "Expected ec48f571-3787-4083-9336-882c4e2de802, got {:?}", result);
    }

    #[test]
    fn get_zone_from_domain_unauthorized() {
        // Mocking
        let data = r#"{
            "code": 401,
            "message": "The server could not verify that you authorized to access the document you requested. Either you supplied the wrong credentials (e.g., bad api key), or your access token has expired",
            "object": "HTTPUnauthorized",
            "cause": "Unauthorized"
        }"#;
        let _m = mock("GET", "/api/v5/zones")
            .with_status(401)
            .with_header("Content-Type", "application/json")
            .with_body(data)
            .create();


        let domain = String::from("fake-domain.tld");
        let api_key = String::from("f4keAp1K3y");

        let zone = get_zone_from_domain(api_key, &domain);

        match zone {
            Ok(_) => assert!(false, "an error should be raised"),
            Err(_) => assert!(true),
        };
    }
}
