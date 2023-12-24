mod frame;
mod packet_parser;

use std::{env, fs, process};
use pnet::datalink;
use rtshark::{RTSharkBuilder, RTSharkBuilderReady};
use frame::{Frame};
use packet_parser::get_frame_info;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [file|interface]", args[0]);
        process::exit(1);
    }

    let file_or_interface = &args[1];
    let mut frames: Vec<Frame> = Vec::new();
    let builder = get_builder(file_or_interface);

    let mut rtshark = builder.spawn().unwrap();

    while let Some(packet) = match rtshark.read() {
        Ok(Some(packet)) => Some(packet),
        Ok(None) => None,
        Err(e) => {
            eprintln!("Error parsing tshark output: {}", e);
            None
        }
    } {
        let frame = get_frame_info(&packet);
        frames.push(frame);
        let frame = frames.last().unwrap();
        println!("{}\t{:.6}\t{}\t{}\t{}\t{}\t{}",
                 frame.get_id(), frame.get_time(), frame.get_source(),
                 frame.get_destination(), frame.get_protocol(),
                 frame.get_length(), frame.get_info());
    }

}

fn get_builder(file_or_interface: &String) -> RTSharkBuilderReady {
    if file_exists(&file_or_interface) {
        let builder = RTSharkBuilder::builder().input_path(&file_or_interface);
        return builder;
    } else if interface_exists(&file_or_interface) {
        let builder = RTSharkBuilder::builder().input_path(&file_or_interface).live_capture();
        return builder;
    } else {
        error_file_nor_interface(&file_or_interface);
    }

    process::exit(0);
}

fn error_file_nor_interface(file_or_interface: &String) {
    if file_or_interface.contains("/") {
        println!("The file {} doesn't exist.", file_or_interface);
    } else {
        println!("The interface {} doesn't exist.", file_or_interface);
    }
}

fn file_exists(file: &str) -> bool {
    fs::metadata(file).is_ok()
}

fn interface_exists(interface: &String) -> bool {
    if datalink::interfaces()
        .iter()
        .any(|iface| iface.name == interface.as_str())
    { true } else { false }
}