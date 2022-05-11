mod errors;
pub use errors::*;
mod base32;
mod bech32m;
pub use bech32m::arbitrary_data_to_bech32m as encode;
pub use bech32m::bech32m_to_arbitrary_data as decode;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Decoded {
    hrp: String,
    data: Vec<u8>,
}

impl Decoded {
    pub fn get_hrp(&self) -> &str {
        &self.hrp
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBase32FromBech32(Decoded);

impl DecodedBase32FromBech32 {
    pub fn new(hrp: String, data: Vec<u8>) -> Self {
        Self(Decoded { hrp, data })
    }

    pub fn get_hrp(&self) -> &str {
        self.0.get_hrp()
    }

    pub fn get_data(&self) -> &[u8] {
        self.0.get_data()
    }

    pub fn encode(&self) -> Result<String, Bech32Error> {
        bech32m::base32_to_bech32m(self.get_hrp(), self.get_data())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedArbitraryDataFromBech32(Decoded);

impl DecodedArbitraryDataFromBech32 {
    pub fn new(hrp: String, data: Vec<u8>) -> Self {
        Self(Decoded { hrp, data })
    }

    pub fn get_hrp(&self) -> &str {
        self.0.get_hrp()
    }

    pub fn get_data(&self) -> &[u8] {
        self.0.get_data()
    }

    pub fn encode(&self) -> Result<String, Bech32Error> {
        bech32m::arbitrary_data_to_bech32m(self.get_hrp(), self.get_data())
    }
}

#[cfg(test)]
mod tests;
