// use std::io::prelude::*;
use byteorder::{BigEndian, ByteOrder, NetworkEndian};
use cpu_time::ProcessTime;
use std::io::{stdout, Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::str;
use std::time::Duration;
use threadpool::ThreadPool;

use config::Config;
use ctrlc;
use curl::easy::{Easy, List};

const BASE_URI: &str = "https://api.trustedservices.intel.com/sgx/dev";
const PATH_SIGRL: &str = "/attestation/v4/sigrl";
const PATH_REPORT: &str = "/attestation/v4/report";

pub mod rap_capnp {
    include!(concat!(env!("OUT_DIR"), "/rap_capnp.rs"));
}

fn main() {
    let settings = Config::builder()
        .add_source(config::File::with_name("Settings"))
        .build()
        .unwrap();

    let spid: String = match settings.get_string("spid") {
        Ok(value) => value,
        Err(error) => panic!("Error fetching SPID: {:?}", error),
    };
    println!("SPID = {}", spid);
    let key: String = match settings.get_string("key") {
        Ok(value) => value,
        Err(error) => panic!("Error fetching secret key: {:?}", error),
    };

    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let pool = ThreadPool::new(4);

    let start = ProcessTime::now();
    ctrlc::set_handler(move || {
        let duration: Duration = start.elapsed();
        println!("Execution time: {:?}", duration);
        // TODO shutdown listener and have duration+print below; not enough rust

        std::process::exit(0);
    })
    .ok();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let key2 = key.to_owned(); // REVIEW

        pool.execute(|| handle_connection(stream, key2));
    }
    // let duration: Duration = start.elapsed();
    // println!("Execution time: {:?}", duration);
}

// retorna mensagem pronta a escrever: o output !!!
fn handle_sigrl(reader: rap_capnp::request_sigrl::Reader, key: String) -> Vec<u8> {
    println!("Handling RequestSigrl...");

    let gid: &str = match reader.get_gid() {
        Ok(gid) => gid,
        Err(e) => "oops, error",
    };
    println!("Result: {}", gid);

    let (code, body) = get_sigrl(gid, key.as_str());

    // prep outer message
    // prep outie
    let mut builder = capnp::message::Builder::new_default();
    let mut response = builder.init_root::<rap_capnp::r_a_p_message::Builder>();

    // prep inner response
    // prep innie
    let mut b2 = capnp::message::Builder::new_default();
    let mut r2 = b2.init_root::<rap_capnp::response_sigrl::Builder>();
    r2.set_code(code);
    r2.set_srl(body.as_slice());

    response
        .set_response_sigrl(r2.reborrow_as_reader())
        .unwrap();

    let mut buffer = Vec::new();
    capnp::serialize::write_message(&mut buffer, &builder).unwrap();

    println!("Writing response to stream...");

    return buffer;
}

fn handle_report(reader: rap_capnp::request_report::Reader, key: String) -> Vec<u8> {
    println!("Handling RequestReport...");

    let input_aep: &str = match reader.get_aep() {
        Ok(t) => t,
        Err(e) => "oops, error",
    };
    println!("Received AEP: {}", input_aep);

    let (code, rid, signature, certificates, body) = get_report(input_aep, key.as_str());

    println!("Response code for get_report: {}", code);

    // prep outie
    let mut builder = capnp::message::Builder::new_default();
    let mut response = builder.init_root::<rap_capnp::r_a_p_message::Builder>();

    // prep innie
    let mut b2 = capnp::message::Builder::new_default();
    let mut r2 = b2.init_root::<rap_capnp::response_report::Builder>();
    r2.set_code(code);
    r2.set_rid(&rid);
    r2.set_signature(&signature);
    r2.set_certificates(&certificates);
    r2.set_avr(body.as_slice());

    response
        .set_response_report(r2.reborrow_as_reader())
        .unwrap();

    let mut buffer = Vec::new();
    capnp::serialize::write_message(&mut buffer, &builder).unwrap();

    println!("Writing response to stream...");

    return buffer;
}

fn handle_connection(mut stream: TcpStream, key: String) {
    println!("Handling new connection...");

    // read length from stream: 4 bytes
    let mut read_len = [0u8; 4];
    stream.read_exact(&mut read_len).unwrap();
    let rlen: u32 = NetworkEndian::read_u32(&read_len);
    println!("read request len: {}", rlen);

    // read serialized data from stream
    let input =
        match capnp::serialize::read_message(&mut stream, capnp::message::ReaderOptions::new()) {
            Ok(t) => t,
            Err(e) => return, // TODO return error? Probably return response that could be an error message!
        };
    let reader = input
        .get_root::<rap_capnp::r_a_p_message::Reader>()
        .unwrap();

    // TODO Como tratar aqui do error handling de forma mais fácil, e como ignore algumas das opções ??
    let output = match reader.which() {
        Ok(rap_capnp::r_a_p_message::Which::Empty(t)) => {
            println!("Entrou no EMPTY !!");
            return;
        }
        Ok(rap_capnp::r_a_p_message::Which::RequestSigrl(t)) => {
            println!("Entrou no request sigrl !!");
            handle_sigrl(
                match t {
                    Ok(t) => t,
                    Err(e) => return,
                },
                key,
            )
        }
        Ok(rap_capnp::r_a_p_message::Which::RequestReport(t)) => {
            println!("Entrou no request report !!");
            handle_report(
                match t {
                    Ok(t) => t,
                    Err(e) => return,
                },
                key,
            )
        }
        Ok(rap_capnp::r_a_p_message::Which::ResponseSigrl(t)) => {
            println!("Entrou no response sigrl !!");
            return;
        }
        Ok(rap_capnp::r_a_p_message::Which::ResponseReport(t)) => {
            println!("Entrou no response report !!");
            return;
        }
        Err(e) => return,
    };

    // write length to stream: 4 bytes
    let mut write_len = [0u8; 4];
    NetworkEndian::write_u32(&mut write_len, output.len() as u32);
    stream.write_all(&write_len).unwrap();

    // write serialized data to stream
    stream.write_all(&mut output.as_slice()).unwrap();
    println!("Wrote response to stream {}.", output.len());
}

fn get_sigrl(gid: &str, key: &str) -> (u32, Vec<u8>) {
    // REVIEW Alguma forma de fazer isto directamente no append? (como o gid?)
    let header = "Ocp-Apim-Subscription-Key: ".to_string();
    let header = header + key;

    let mut list = List::new();
    list.append(&header).unwrap();

    let mut data = Vec::new();
    let mut easy = Easy::new();
    easy.url(&(BASE_URI.to_owned() + PATH_SIGRL + "/" + gid))
        .unwrap();
    easy.http_headers(list).unwrap();
    {
        let mut transfer = easy.transfer();
        transfer
            .write_function(|new_data| {
                data.extend_from_slice(new_data);
                Ok(new_data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }

    println!("Response code: {}", easy.response_code().unwrap());

    return (easy.response_code().unwrap(), data);
}

// Return aqui é: HTTP response code, report signature, report certificates, body
fn get_report(aep: &str, key: &str) -> (u32, String, String, String, Vec<u8>) {
    let mut input = aep.as_bytes();

    let mut list = List::new();
    list.append("Content-Type: application/json").unwrap();
    list.append(&("Ocp-Apim-Subscription-Key: ".to_owned() + key))
        .unwrap();

    let mut rid: String = String::new();
    let mut signature: String = String::new();
    let mut certificates: String = String::new();

    let mut output = Vec::new();
    let mut easy = Easy::new();
    easy.url(&(BASE_URI.to_owned() + PATH_REPORT)).unwrap();
    easy.post(true).unwrap();
    easy.post_field_size(input.len() as u64).unwrap();
    easy.http_headers(list).unwrap();
    {
        let mut transfer = easy.transfer();
        transfer
            .read_function(|new_data| Ok(input.read(new_data).unwrap()))
            .unwrap();
        transfer
            .header_function(|h| {
                let s2: Vec<&str> = str::from_utf8(h).unwrap().trim().split(": ").collect();
                if s2[0] == "Request-ID" {
                    println!("header rid:  {}", s2[1]);
                    rid = s2[1].to_string();
                } else if s2[0] == "X-IASReport-Signature" {
                    println!("header sig:  {}", s2[1]);
                    signature = s2[1].to_string();
                } else if s2[0] == "X-IASReport-Signing-Certificate" {
                    println!("header cert: {}", s2[1]);
                    certificates = s2[1].to_string();
                }
                true
            })
            .unwrap();
        transfer
            .write_function(|get_data| {
                output.extend_from_slice(get_data);
                Ok(get_data.len())
            })
            .unwrap();
        transfer.perform().unwrap();
    }

    return (
        easy.response_code().unwrap(),
        rid,
        signature,
        certificates,
        output,
    );
}
