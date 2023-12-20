pub struct Frame {
    pub number: usize,
    pub time: String,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub length: u32,
    pub info: String,
}

pub fn update_frame_id(frame: &mut Frame, frames: &Vec<Frame>) {
    frame.number = frames.len() + 1;
}