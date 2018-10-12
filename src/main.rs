#[macro_use]
extern crate serde_derive;

#[cfg(test)]
extern crate tempdir;

extern crate serde_json;
extern crate reqwest;
extern crate clap;
extern crate ini;
use ini::Ini;
use clap::{Arg, App};
use std::process::exit;

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


    Ok(Config{
        api_key,
        records,
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

    let config = match load_config(config_file) {
        Ok(v) => v,
        Err(e) => {
            println!("{}", e);
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

    let client = reqwest::Client::new();

    for record in config.records {
        let r = Record{
            rrset_values: vec![ip.to_owned()],
        };

        let response = client
        .put(&format!("https://dns.api.gandi.net/api/v5/zones/XXXXXXXXXXXXXXXX/records/{}/A", record))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Api-Key", config.api_key.to_owned())
        .body(serde_json::to_string(&r).unwrap())
        .send().unwrap();

        if response.status().is_success() {
            println!("Record updated!");
        } else {
            println!("Record updated failed.")
        }
    }
    return 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::prelude::*;
    use std::fs;
    use tempdir::TempDir;


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
}
