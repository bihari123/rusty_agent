use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigChangeRequest {
    pub propertyName: String,
    pub propertyValue: String,
}

impl fmt::Display for ConfigChangeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ \n \t\"property_name\": {}\n \t\"property_val\": {:?}\n }}",
            self.propertyName, self.propertyValue,
        )
    }
}
