use crate::enums::KzgError;
use crate::kzg_proof::safe_scalar_affine_from_bytes;
use crate::{BYTES_PER_BLOB, BYTES_PER_FIELD_ELEMENT};

use alloc::{boxed::Box, string::ToString, vec::Vec};
use bls12_381::Scalar;

macro_rules! define_bytes_type {
    ($name:ident, $size:expr) => {
        #[derive(Debug, Clone)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name(#[cfg_attr(feature = "serde", serde(with = "serde_bytes"))] [u8; $size]);

        impl $name {
            pub fn from_slice(slice: &[u8]) -> Result<Self, KzgError> {
                if slice.len() != $size {
                    return Err(KzgError::InvalidBytesLength(
                        "Invalid slice length".to_string(),
                    ));
                }
                let mut bytes = [0u8; $size];
                bytes.copy_from_slice(slice);
                Ok($name(bytes))
            }

            pub fn as_slice(&self) -> &[u8] {
                &self.0
            }

            pub fn boxed(self) -> Box<[u8; $size]> {
                Box::new(self.0)
            }
        }

        impl From<$name> for [u8; $size] {
            fn from(value: $name) -> [u8; $size] {
                value.0
            }
        }
    };
}

define_bytes_type!(Bytes32, 32);
define_bytes_type!(Bytes48, 48);

#[derive(Debug, Clone)]
pub struct Blob {
    _inner: Box<[u8; 131072]>,
}

#[cfg(feature = "serde")]
impl serde::Serialize for Blob {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self._inner.as_slice())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Blob {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let inner = <Vec<u8>>::deserialize(deserializer)?;
        match inner.into_boxed_slice().try_into() {
            Ok(v) => Ok(Self { _inner: v }),
            Err(_) => Err(serde::de::Error::custom("Blob must be 131072 bytes long")),
        }
    }
}

impl Blob {
    pub fn from_slice(slice: &[u8]) -> Result<Self, KzgError> {
        if slice.len() != BYTES_PER_BLOB {
            return Err(KzgError::InvalidBytesLength(
                "Invalid slice length".to_string(),
            ));
        }

        let mut bytes = Box::new([0u8; BYTES_PER_BLOB]);
        bytes.copy_from_slice(slice);
        Ok(Blob { _inner: bytes })
    }
    pub fn as_slice(&self) -> &[u8] {
        &*self._inner
    }
    pub fn boxed(self) -> Box<[u8; BYTES_PER_BLOB]> {
        Box::new(self.into())
    }
}
impl From<Blob> for [u8; BYTES_PER_BLOB] {
    fn from(value: Blob) -> [u8; BYTES_PER_BLOB] {
        *value._inner
    }
}

impl Blob {
    pub fn as_polynomial(&self) -> Result<Vec<Scalar>, KzgError> {
        self._inner
            .chunks(BYTES_PER_FIELD_ELEMENT)
            .map(|slice| {
                Bytes32::from_slice(slice).and_then(|bytes| safe_scalar_affine_from_bytes(&bytes))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_bytes32() {
        let bytes = crate::dtypes::Bytes32::from_slice(&[0u8; 32]).unwrap();
        assert_eq!(bytes.0.len(), 32);
    }

    #[test]
    fn test_bytes48() {
        let bytes = crate::dtypes::Bytes48::from_slice(&[0u8; 48]).unwrap();
        assert_eq!(bytes.0.len(), 48);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn roundtrip_serde_blob() {
        let blob = super::Blob::from_slice(&[0u8; 131072]).unwrap();
        let ser = bincode::serialize(&blob).unwrap();
        let _deser: super::Blob = bincode::deserialize(&ser).unwrap();
    }
}
