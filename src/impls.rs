// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

/// Macro used for deriving `serde`'s `Serialize` and `Deserialize` traits.
macro_rules! impl_serialize_and_deserialize_for {
    ($item:ident) => {
        #[cfg(feature = "serde")]
        impl<G: Group, H: BlockInput + Digest> serde_::Serialize for $item<G, H> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde_::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&base64::encode(&self.serialize()))
                } else {
                    serializer.serialize_bytes(&self.serialize())
                }
            }
        }

        #[cfg(feature = "serde")]
        impl<'de, G: Group, H: BlockInput + Digest> serde_::Deserialize<'de> for $item<G, H> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde_::Deserializer<'de>,
            {
                use serde_::de::Error;

                if deserializer.is_human_readable() {
                    let s = <&str>::deserialize(deserializer)?;
                    Self::deserialize(&base64::decode(s).map_err(Error::custom)?)
                        .map_err(Error::custom)
                } else {
                    struct ByteVisitor<G: Group, H: BlockInput + Digest>(core::marker::PhantomData<(G, H)>);

                    impl<'de, G: Group, H: BlockInput + Digest> serde_::de::Visitor<'de> for ByteVisitor<G, H> {
                        type Value = $item<G, H>;

                        fn expecting(
                            &self,
                            formatter: &mut core::fmt::Formatter,
                        ) -> core::fmt::Result {
                            formatter.write_str(core::concat!(
                                "the byte representation of a ",
                                core::stringify!($item)
                            ))
                        }

                        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                        where
                            E: Error,
                        {
                            $item::<G, H>::deserialize(value).map_err(|_| {
                                Error::invalid_value(
                                    serde_::de::Unexpected::Bytes(value),
                                    &core::concat!(
                                        "invalid byte sequence for ",
                                        core::stringify!($item)
                                    ),
                                )
                            })
                        }
                    }

                    deserializer
                        .deserialize_bytes(ByteVisitor::<G, H>(core::marker::PhantomData))
                        .map_err(Error::custom)
                }
            }
        }
    };
}
