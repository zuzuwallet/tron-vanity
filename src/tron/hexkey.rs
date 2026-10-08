//! 64-character lowercase hex form of a 32-byte private key.
//!
//! This is the text TRON wallets show. It is not Bitcoin WIF, and it has no
//! `0x` prefix. The encoded text is a `SecretString`. Decode builds a
//! `Zeroizing` array and moves it into `SecretBytes`.

use zeroize::Zeroizing;

use crate::error::Error;
use crate::secret::{SecretBytes, SecretString};

pub fn encode_hex_key(key: &[u8; 32]) -> SecretString {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in key {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    SecretString::new(out)
}

pub fn decode_hex_key(text: &str) -> Result<SecretBytes<32>, Error> {
    if text.len() != 64 {
        return Err(Error::InvalidKeyText);
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (index, byte) in out.iter_mut().enumerate() {
        let pair = text
            .as_bytes()
            .get(index * 2..index * 2 + 2)
            .ok_or(Error::InvalidKeyText)?;
        if !pair
            .iter()
            .all(|char| char.is_ascii_hexdigit() && !char.is_ascii_uppercase())
        {
            return Err(Error::InvalidKeyText);
        }
        let text = std::str::from_utf8(pair).map_err(|_| Error::InvalidKeyText)?;
        *byte = u8::from_str_radix(text, 16).map_err(|_| Error::InvalidKeyText)?;
    }
    let encoded = encode_hex_key(&out);
    if encoded.as_str() != text {
        return Err(Error::InvalidKeyText);
    }
    Ok(SecretBytes::from_zeroizing(out))
}

#[cfg(test)]
mod tests {
    use super::{decode_hex_key, encode_hex_key};
    use crate::Error;

    #[test]
    fn lowercase_hex_round_trips_and_rejects_other_forms() {
        let mut key = [0u8; 32];
        key[31] = 1;
        let text = encode_hex_key(&key);
        assert_eq!(text.as_str().len(), 64);
        assert!(text.as_str().ends_with('1'));
        assert!(!format!("{text:?}").contains(text.as_str()));
        let decoded = decode_hex_key(text.as_str()).unwrap();
        assert_eq!(decoded.as_bytes(), &key);

        let mut chars: Vec<u8> = text.as_str().as_bytes().to_vec();
        chars[63] = b'A';
        let upper = String::from_utf8(chars).unwrap();
        assert!(matches!(decode_hex_key(&upper), Err(Error::InvalidKeyText)));
        assert!(matches!(
            decode_hex_key(&format!("0x{}", text.as_str())),
            Err(Error::InvalidKeyText)
        ));
        assert!(matches!(decode_hex_key("zz"), Err(Error::InvalidKeyText)));
        assert!(matches!(
            decode_hex_key(&text.as_str()[..63]),
            Err(Error::InvalidKeyText)
        ));
    }
}
