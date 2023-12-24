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

fn get_tls(metadata: &String) -> String {
    let mut tls_version = "TLS".to_string();

    for line in metadata.lines() {
        if line.trim().starts_with("TLSv1.") {
            let tls_version = line.split_whitespace().next().unwrap_or_default();
            return tls_version.to_string();
        }
    }

    return tls_version;
}

pub fn get_frame_info(packet: &Packet) -> Frame {
    let metadata = parse_packet_data(&packet);

    Frame::new(
        get_packet_metadata(&metadata),
        get_id(&metadata),
        get_time(&metadata),
        get_source(&metadata),
        get_destination(&metadata),
        get_protocol(&metadata),
        get_length(&metadata),
        get_info(&metadata))
}

pub fn get_packet_metadata(metadata: &String) -> String {
    metadata.parse().unwrap()
}

fn get_id(metadata: &String) -> usize {
    let mut id = 0;
    for line in metadata.lines() {
        if line.trim().starts_with("Frame Number:") {
            if let Some(types) = line.split(':').nth(1) {
                id = types.trim().parse().unwrap();
            }
            return id;
        }
    }

    id
}

fn get_time(metadata: &String) -> f64 {
    let mut time = 0.0;

    for line in metadata.lines() {
        if line.trim().starts_with("Time since reference or first frame:") {
            if let Some(_time_str) = line.split(':').nth(1) {
                let numeric_str: String = _time_str.chars().filter(|&c| c.is_digit(10) || c == '.').collect();
                if let Ok(parsed_value) = numeric_str.parse::<f64>() {
                    time = parsed_value;
                }
            }
        }
    }

    time
}

fn get_source(metadata: &String) -> String {
    String::new()
}
fn get_destination(metadata: &String) -> String {
    String::new()
}

fn get_protocol(metadata: &String) -> String {
    let mut protocol = String::new();

    for line in metadata.lines() {
        if line.trim().starts_with("Protocols in frame:") {
            let mut protocols: Vec<&str> = line.split(':').map(|s| s.trim()).collect();

            if protocols.contains(&"data") && metadata.contains("Unknown") {
                protocol = "0x7373".to_string();
                return protocol;
            } else {
                protocols.retain(|&word| !word.contains("data") && !word.contains("mime"));
                protocol = protocols.last().unwrap().to_uppercase().to_string();
            }

            if protocol == "TLS" {
                protocol = get_tls(&metadata);
            }

            break;
        }
    }

    protocol
}

fn get_length(metadata: &String) -> i32 {
    0
}

fn get_info(metadata: &String) -> String {
    String::new()
}