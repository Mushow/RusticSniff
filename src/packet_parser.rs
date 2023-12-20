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

pub fn get_frame_info(metadata: Vec<&str>) -> Frame {
    Frame {
        number: 0,
        time: get_time(&metadata),
        source: get_source(&metadata),
        destination: get_destination(&metadata),
        protocol: get_protocol(&metadata),
        length: get_length(&metadata),
        info: get_info(&metadata),
    }
}


fn get_info(packet: &Vec<&str>) -> String {
    "".to_string()
}

fn get_length(packet: &Vec<&str>) -> u32 {
    0
}

fn get_protocol(packet: &Vec<&str>) -> String {
    "".to_string()
}

fn get_destination(packet: &Vec<&str>) -> String {
    "".to_string()
}

fn get_source(packet: &Vec<&str>) -> String {
    "".to_string()
}

fn get_time(packet: &Vec<&str>) -> String {
    "".to_string()
}