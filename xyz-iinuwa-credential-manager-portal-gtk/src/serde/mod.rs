pub(crate) mod b64 {
    use base64::{self, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<S>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = URL_SAFE_NO_PAD.encode(value);
        String::serialize(&s, serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD.decode(s).map_err(de::Error::custom)
    }
}

pub(crate) mod duration {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub(crate) fn from_opt_ms<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<u32>::deserialize(deserializer)
            .map(|ms_opt| ms_opt.map(|ms| Duration::from_millis(ms as u64)))
    }
}
