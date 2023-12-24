use rtshark::Packet;
use crate::frame::Frame;

pub fn parse_packet_data(packet: &Packet) -> String {
    packet
        .iter()
        .flat_map(|layer| layer.iter().map(|data| format!("{}\n", data.display())))
        .collect()
}

fn get_type(metadata: &String) -> String {
    let mut packet_type = "Protocol not found".to_string();

    for line in metadata.lines() {
        if line.trim().starts_with("Type:") {
            if let Some(types) = line.split(':').nth(1) {
                packet_type = types.trim().to_string();
            }
            return packet_type;
        }
    }

    return packet_type;
}


pub fn get_frame_info(packet: &Packet) -> Frame {
    let metadata = parse_packet_data(&packet);

    Frame::new(
        get_packet_metadata(&packet),
        0,
        get_time(&metadata),
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
fn get_time(metadata: &String) -> f64 {
    //metadata.contains()
    0.000000
}

fn get_source(metadata: &String) -> String {
    "".to_string()
}
fn get_destination(metadata: &String) -> String {
    "".to_string()
}

fn get_protocol(metadata: &String) -> String {
    let mut protocol = "Protocol not found".to_string();

    for line in metadata.lines() {
        if line.trim().starts_with("Protocols in frame:") {
            if let Some(protocols) = line.split(':').last() {
                protocol = protocols.trim().to_uppercase().to_string();
            }
            break;
        }
    }

    let packet_type = get_type(metadata);

    if protocol == "DATA" && packet_type.contains("Unknown") {
        protocol = "0x7373".to_string();
    }

    protocol
}

fn get_length(metadata: &String) -> i32 {
    0
}

fn get_info(metadata: &String) -> String {
    "".to_string()
}