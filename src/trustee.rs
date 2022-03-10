struct Trustee {
    id: u32,
    m: u32,
}

impl Trustee {
    fn get_t(&self) -> u32 {
        self.m-1
    }
}