pub struct Frame {
    global_info: String,
    id: usize,
    time: f64,
    source: String,
    destination: String,
    protocol: String,
    length: i32,
    info: String,
}

impl Frame {
    pub fn new(
        global_info: String, id: usize, time: f64,
        source: String, destination: String, protocol: String,
        length: i32, info: String,
    ) -> Self {
        Self {
            global_info,
            id,
            time,
            source,
            destination,
            protocol,
            length,
            info,
        }
    }


    pub fn get_global_info(&self) -> &String {
        &self.global_info
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_time(&self) -> f64 {
        self.time
    }

    pub fn get_source(&self) -> &String {
        &self.source
    }

    pub fn get_destination(&self) -> &String {
        &self.destination
    }

    pub fn get_protocol(&self) -> &String {
        &self.protocol
    }

    pub fn get_length(&self) -> i32 {
        self.length
    }

    pub fn get_info(&self) -> &String {
        &self.info
    }
}
