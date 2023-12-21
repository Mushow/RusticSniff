use rtshark::Packet;
use crate::frame::Frame;

pub fn parse_packet(packet: &rtshark::Packet) -> Vec<&str> {
    let mut metadata = Vec::new();

    for layer in packet.iter() {
        for data in layer.iter() {
            metadata.push(data.display());
        }
    }

    metadata
}

pub fn get_frame_info(packet: &Packet) -> Frame {
    let metadata = parse_packet(&packet);

    Frame::new(
        get_packet_metadata(&packet),
        0,
        0.0,
        get_source(&metadata),
        get_destination(&metadata),
        get_protocol(&metadata),
        get_length(&metadata),
        get_info(&metadata))
}

pub fn get_packet_metadata(packet: &Packet) -> String {
    packet
        .iter()
        .flat_map(|layer| layer.iter().map(|data| format!("{}\n", data.display())))
        .collect()
}
fn get_time(packet: &Vec<&str>) -> f64 {
    0.0
}

fn get_source(packet: &Vec<&str>) -> String {
    "".to_string()
}
fn get_destination(packet: &Vec<&str>) -> String {
    "".to_string()
}

fn get_protocol(packet: &Vec<&str>) -> String {
    "".to_string()
}
fn get_length(packet: &Vec<&str>) -> u32 {
    0
}
fn get_info(packet: &Vec<&str>) -> String {
    "".to_string()
}