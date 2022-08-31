// use std::io::prelude::*;
use byteorder::{BigEndian, ByteOrder, NetworkEndian};
use std::io::{stdout, Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::str;
use threadpool::ThreadPool;

use curl::easy::{Easy, List};

const BASE_URI: &str = "https://api.trustedservices.intel.com/sgx/dev";
const PATH_SIGRL: &str = "/attestation/v4/sigrl";
const PATH_REPORT: &str = "/attestation/v4/report";

// TEMP de onde virá isto ?
const SPID: &str = "** ESCONDIDO **";
const KEY: &str = "** ESCONDIDO **";

struct AEP {
    quote: String,
    nonce: String,
}

// TODO: talvez separar rede (uma função) de pré-processamento (outra função) e de pós-processamento (outra função). E também de protocolo de comunicação com clientes (outras funções).
struct AVR {
    quote: String,
    nonce: String,
}

pub mod rap_capnp {
    include!(concat!(env!("OUT_DIR"), "/rap_capnp.rs"));
}

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let pool = ThreadPool::new(4);

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();

        pool.execute(|| handle_connection(stream));
    }

    //
    //
    //

    let spid = "** ESCONDIDO **";
    let key = "** ESCONDIDO **";
    // let mut gid: [u8; 4] = [0x00, 0x00, 0x0b, 0x32];
    let gid = "** ESCONDIDO **";

    println!("SPID = {}, key = {}, gid = {:02x?}", spid, key, gid);

    let (code, body) = get_sigrl(gid, key);

    println!("{:?}", body); // responde body?
    println!("Response code for get_sigrl: {}", code);

    // let mut easy = Easy::new();
    // easy.url("https://rust-lang.org/").unwrap();
    // easy.write_function(|data| {
    //     stdout().write_all(data).unwrap();
    //     Ok(data.len())
    // })
    // .unwrap();
    // easy.perform().unwrap();
    // println!("{}", easy.response_code().unwrap());

    // TORM obsolete
    // let aep = AEP {
    //     quote: String::from(""),
    //     nonce: String::from(""),
    // };
    // let (code, a, b, body) = get_report(aep, key);
    //
    // println!("Response code for get_report: {}", code);
}

// fn handle_sigrl(capnp::message::Reader: reader) {}

// // Retorna tamanho a escrever e... melhor não fazer assim? Tamanho vem de len. Talvez status ou só o vector?
// fn handle_sigrl_2(r: core::result::Result<Ok, Err>) -> Vec<u8> {
//     // return (0, vec![0u8; 4096]);
//     return vec![0u8; 4096];
// }
// retorna mensagem pronta a escrever: o output !!!
fn handle_sigrl(reader: rap_capnp::request_sigrl::Reader) -> Vec<u8> {
    println!("Handling RequestSigrl...");

    // let reader = deserialized
    //     .get_root::<rap_capnp::request_sigrl::Reader>()
    //     .unwrap();

    let gid: &str = match reader.get_gid() {
        Ok(gid) => gid,
        Err(e) => "oops, error",
    };
    println!("Result: {}", gid);

    let (code, body) = get_sigrl(gid, KEY);

    // let mut builder = capnp::message::Builder::new_default();
    // let mut response = builder.init_root::<rap_capnp::message::Builder>();
    // response.set_response_sigrl(value)

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

    // return (0, vec![0u8; 4096]);
    // return vec![0u8; 4096];
    return buffer;
}

fn handle_report(reader: rap_capnp::request_report::Reader) -> Vec<u8> {
    println!("Handling RequestReport...");
    // return (0, vec![0u8; 4096]);

    let input_aep: &str = match reader.get_aep() {
        Ok(t) => t,
        Err(e) => "oops, error",
    };
    println!("Received AEP: {}", input_aep);

    // let nonce: &str = match reader.get_nonce() {
    //     Ok(t) => t,
    //     Err(e) => "oops, error",
    // };
    // println!("Result: {}", nonce);

    // let aep = AEP {
    //     quote: String::from(""),
    //     nonce: String::from(""),
    // };
    // let (code, a, b, body) = get_report(aep, KEY);
    let (code, rid, signature, certificates, body) = get_report(input_aep, KEY);

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

    // return vec![0u8; 4096];
    return buffer;
}

fn handle_connection(mut stream: TcpStream) {
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
        // Ok(rap_capnp::message::Which::Empty(t)) => handle_sigrl_2(t),
        Ok(rap_capnp::r_a_p_message::Which::RequestSigrl(t)) => {
            println!("Entrou no request sigrl !!");
            handle_sigrl(match t {
                Ok(t) => t,
                Err(e) => return,
            })
        }
        Ok(rap_capnp::r_a_p_message::Which::RequestReport(t)) => {
            println!("Entrou no request report !!");
            handle_report(match t {
                Ok(t) => t,
                Err(e) => return,
            })
        }
        Ok(rap_capnp::r_a_p_message::Which::ResponseSigrl(t)) => {
            println!("Entrou no response sigrl !!");
            return;
        }
        Ok(rap_capnp::r_a_p_message::Which::ResponseReport(t)) => {
            println!("Entrou no response report !!");
            return;
        }
        // Ok(rap_capnp::message::Which::ResponseSigrl(t)) => handle_sigrl_2(t),
        // Ok(rap_capnp::message::Which::ResponseReport(t)) => handle_sigrl_2(t),
        // _ => {
        //     println!("Entrou no _ !!");
        //     return;
        // } // para não fazer match às responses user antes isto
        // _ => return, // para não fazer match às responses user antes isto
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

// TODO Como extrair da função o status e o body?
//      Pensar no formato de inter-computer protocol para saber. flat buffers?

// fn get_sigrl(gid: [u8; 4], key: &str) {
fn get_sigrl(gid: &str, key: &str) -> (u32, Vec<u8>) {
    // do nothing for now

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
    // easy.perform().unwrap();

    // println!("{:?}", data); // responde body?
    println!("Response code: {}", easy.response_code().unwrap());

    return (easy.response_code().unwrap(), data);
}

// FIXME se AEP já vai preparada em vez de estrutura então tratar disso cá fora e aqui passar string ou bytes. Alternativa é enviar e receber estrutura já demonstrada e faer tudo lá dentro. // Talvez esta segunda alternativa melhor que encaixa depois ao passar dados para o protobuf?
// (Mais importante é protobuf estar estável porque é API externa!)
// Return aqui é: HTTP response code, report signature, report certificates, body
fn get_report(aep: &str, key: &str) -> (u32, String, String, String, Vec<u8>) {
    // TODO prepare AEP struycture using IAS accepted format: JSON
    // let mut input = "this should be serialized aep".as_bytes();
    let mut input = aep.as_bytes();

    let mut list = List::new();
    list.append("Content-Type: application/json").unwrap();
    list.append(&("Ocp-Apim-Subscription-Key: ".to_owned() + key))
        .unwrap();

    // for e in list.iter() {
    //     println!("List has element: {:?}", e);
    // }

    // FIXME  These two not getting set, how to do it ??
    // let report_signature = Vec::new(); // does nothing, fix
    // let report_certificates = Vec::new(); // does nothing, fix
    // let mut headers = Vec::new();
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
            .read_function(|new_data| {
                // output.extend_from_slice(new_data); // É isto que mete reply ??
                // Ok(new_data.len())
                Ok(input.read(new_data).unwrap())
                //
                // TODO  E agora, como vou buscar o resultado ??
                //       E os headers resposta !?
                //
            })
            .unwrap();
        transfer
            .header_function(|h| {
                // headers.push(str::from_utf8(h).unwrap().to_string());
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
    // println!("headers:\n {:?}", headers);
    // for x in &headers {
    //     println!("header: {}", x);
    // }
    // println!("body:\n {:?}", output);
    // easy.perform().unwrap();

    // println!("{:?}", output); // responde body?
    // println!("Response code: {}", easy.response_code().unwrap());

    return (
        easy.response_code().unwrap(),
        rid,
        signature,
        certificates,
        output,
    );
}
