pub struct Frame {
    global_info: String,
    id: usize,
    time: f64,
    source: String,
    destination: String,
    protocol: String,
    length: u32,
    info: String,
}

impl Frame {
    pub fn new(global_info: String, id: usize, time: f64, source: String, destination: String, protocol: String, length: u32, info: String) -> Self {
        Self { global_info, id, time, source, destination, protocol, length, info }
    }

    pub fn get_global_info(&self) -> &String {
        &self.global_info
    }

    pub fn set_global_info(&mut self, new_info: String) {
        self.global_info = new_info;
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn set_id(&mut self, new_id: usize) {
        self.id = new_id;
    }

    pub fn get_time(&self) -> f64 {
        self.time
    }

    pub fn set_time(&mut self, new_time: f64) {
        self.time = new_time;
    }

    pub fn get_source(&self) -> &String {
        &self.source
    }

    pub fn set_source(&mut self, new_source: String) {
        self.source = new_source;
    }

    pub fn get_destination(&self) -> &String {
        &self.destination
    }

    pub fn set_destination(&mut self, new_destination: String) {
        self.destination = new_destination;
    }

    pub fn get_protocol(&self) -> &String {
        &self.protocol
    }

    pub fn set_protocol(&mut self, new_protocol: String) {
        self.protocol = new_protocol;
    }

    pub fn get_length(&self) -> u32 {
        self.length
    }

    pub fn set_length(&mut self, new_length: u32) {
        self.length = new_length;
    }

    pub fn get_info(&self) -> &String {
        &self.info
    }

    pub fn set_info(&mut self, new_info: String) {
        self.info = new_info;
    }
}

pub fn update_frame_id(frame: &mut Frame, frames: &Vec<Frame>) {
    frame.set_id(frames.len() + 1);
}
