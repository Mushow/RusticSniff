use rtshark::Packet;
use crate::frame::Frame;

pub fn parse_packet_data(packet: &Packet) -> String {
    packet
        .iter()
        .flat_map(|layer| layer.iter().map(|data| format!("{}\n", data.display())))
        .collect()
}

fn get_tls(metadata: &String) -> String {
    let mut tls_version = "TLS".to_string();

    for line in metadata.lines() {
        if line.trim().starts_with("TLSv1.") {
            tls_version = line.split_whitespace().next().unwrap().to_string();
        }
    }

    return tls_version;
}

pub fn get_frame_info(packet: &Packet) -> Frame {
    let metadata = parse_packet_data(&packet);

    Frame::new(
        get_packet_metadata(&metadata),
        extract_id(&metadata),
        extract_time(&metadata),
        extract_source(&metadata),
        extract_destination(&metadata),
        extract_protocol(&metadata),
        extract_frame_length(&metadata),
        get_info(&metadata))
}

fn extract_time(metadata: &String) -> f64 {
    extract_numeric(&metadata, "Time since reference or first frame:")
}

fn extract_id(metadata: &String) -> usize {
    extract_field(&metadata, "Frame Number:").parse().unwrap_or(0)
}

fn extract_frame_length(metadata: &String) -> i32 {
    extract_field(&metadata, "Frame Length:")
        .split("bytes")
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

pub fn get_packet_metadata(metadata: &String) -> String {
    metadata.parse().unwrap()
}

fn extract_field(metadata: &str, field: &str) -> String {
    metadata
        .lines()
        .find(|line| line.trim().starts_with(field))
        .map(|line| line.split(':').nth(1).map(|s| s.trim().to_string()).unwrap_or_default())
        .unwrap_or_default()
}

fn extract_numeric(metadata: &str, field: &str) -> f64 {
    metadata
        .lines()
        .find(|line| line.trim().starts_with(field))
        .and_then(|line| line.split(':').nth(1).map(|s| s.trim()))
        .and_then(|_time_str| {
            let numeric_str: String = _time_str.chars().filter(|&c| c.is_digit(10) || c == '.').collect();
            numeric_str.parse().ok()
        })
        .unwrap_or(0.0)
}

fn extract_source(metadata: &str) -> String {
    let source_line = metadata
        .lines()
        .find(|line| line.starts_with("Source Address:"))
        .or_else(|| metadata.lines().find(|line| line.starts_with("Source:")))
        .unwrap_or_default();

    extract_address_from_line(source_line)
}

fn extract_destination(metadata: &str) -> String {
    let destination_line = metadata
        .lines()
        .find(|line| line.starts_with("Destination Address:"))
        .or_else(|| metadata.lines().find(|line| line.starts_with("Destination:")))
        .unwrap_or_default();

    extract_address_from_line(destination_line)
}

fn extract_address_from_line(line: &str) -> String {
    let start_idx = line.find(':').unwrap_or(0);
    line[start_idx + 2..].trim().to_string()
}

fn extract_protocol(metadata: &String) -> String {
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

fn get_info(_metadata: &String) -> String {
    String::new()
}