// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

macro_rules! impl_debug_eq_hash_for {
    (struct $name:ident$(<$($gen:ident$(: $bound1:tt$( + $bound2:tt)*)?),+$(,)?>)?, [$field1:ident$(, $field2:ident)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound1$( + $bound2)*)?),+>)? core::fmt::Debug for $name$(<$($gen),+>)?
        $(where $($type: core::fmt::Debug,)+)?
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_struct("$name")
                .field("$field1", &self.$field1)
                $(.field("$field2", &self.$field2))*
                .finish()
            }
        }

        impl$(<$($gen$(: $bound1$( + $bound2)*)?),+>)? Eq for $name$(<$($gen),+>)?
        $(where $($type: Eq,)+)?
        {}

        impl$(<$($gen$(: $bound1$( + $bound2)*)?),+>)? PartialEq for $name$(<$($gen),+>)?
        $(where $($type: PartialEq,)+)?
        {
            fn eq(&self, other: &Self) -> bool {
                PartialEq::eq(&self.$field1, &other.$field1)
                $(&& PartialEq::eq(&self.$field2, &other.$field2))*
            }
        }

        impl$(<$($gen$(: $bound1$( + $bound2)*)?),+>)? core::hash::Hash for $name$(<$($gen),+>)?
        $(where $($type: core::hash::Hash,)+)?
        {
            fn hash<_H: core::hash::Hasher>(&self, state: &mut _H) {
                core::hash::Hash::hash(&self.$field1, state);
                $(core::hash::Hash::hash(&self.$field2, state);)*
            }
        }
    };
    (tuple $name:ident$(<$($gen:ident$(: $bound1:tt$( + $bound2:tt)*)?),+$(,)?>)?, [$field1:tt$(, $field2:tt)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? core::fmt::Debug for $name$(<$($gen),+>)?
        $(where $($type: core::fmt::Debug,)+)?
        {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple("$name")
                .field(&self.$field1)
                $(.field(&self.$field2))*
                .finish()
            }
        }

        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? Eq for $name$(<$($gen),+>)?
        $(where $($type: Eq,)+)?
        {}

        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? PartialEq for $name$(<$($gen),+>)?
        $(where $($type: PartialEq,)+)?
        {
            fn eq(&self, other: &Self) -> bool {
                PartialEq::eq(&self.$field1, &other.$field1)
                $(&& PartialEq::eq(&self.$field2, &other.$field2))*
            }
        }

        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? core::hash::Hash for $name$(<$($gen),+>)?
        $(where $($type: core::hash::Hash,)+)?
        {
            fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
                core::hash::Hash::hash(&self.$field1, state);
                $(core::hash::Hash::hash(&self.$field2, state);)*
            }
        }
    };
}

macro_rules! impl_clone_for {
    (struct $name:ident$(<$($gen:ident$(: $bound1:tt$( + $bound2:tt)*)?),+$(,)?>)?, [$field1:ident$(, $field2:ident)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? Clone for $name$(<$($gen),+>)?
        $(where $($type: Clone,)+)?
        {
            fn clone(&self) -> Self {
                Self {
                    $field1: self.$field1.clone(),
                    $($field2: self.$field2.clone(),)*
                }
            }
        }
    };
    (tuple $name:ident$(<$($gen:ident$(: $bound1:tt$( + $bound2:tt)*)?),+$(,)?>)?, [$field1:tt$(, $field2:tt)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? Clone for $name$(<$($gen),+>)?
        $(where $($type: Clone,)+)?
        {
            fn clone(&self) -> Self {
                Self(
                    self.$field1.clone(),
                    $(self.$field2.clone(),)*
                )
            }
        }
    };
}

macro_rules! impl_zeroize_field_skip_pd {
    ($self_:ident, $field:ident, PH) => {};
    ($self_:ident, $field:ident) => {
        $self_.$field.zeroize();
    };
}

macro_rules! impl_zeroize_on_drop_for {
    (struct $name:ident$(<$($gen:ident$(: $bound1:tt$( + $bound2:tt)*)?),+$(,)?>)?, [$(#[$pd1:ident] )?$field1:ident$(, $(#[$pd2:ident] )?$field2:ident)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? zeroize::Zeroize for $name$(<$($gen),+>)?
        {
            fn zeroize(&mut self) {
                impl_zeroize_field_skip_pd!(self, $field1$(, $pd1)?);
                $(impl_zeroize_field_skip_pd!(self, $field2$(, $pd2)?);)*
            }
        }

        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? Drop for $name$(<$($gen),+>)?
        {
            fn drop(&mut self) {
                #[allow(unused_imports)]
                use zeroize::Zeroize;
                impl_zeroize_field_skip_pd!(self, $field1$(, $pd1)?);
                $(impl_zeroize_field_skip_pd!(self, $field2$(, $pd2)?);)*
            }
        }
    };
}

/// Inner macro used for deriving `serde`'s `Serialize` and `Deserialize` traits.
macro_rules! impl_serialize_and_deserialize_for {
    ($name:ident$(<$($gen:ident$(: $bound1:tt$( + $bound2:tt)*)?),+$(,)?>)?) => {
        #[cfg(feature = "serialize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serialize")))]
        impl$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)? serde::Serialize for $name$(<$($gen),+>)? {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                if serializer.is_human_readable() {
                    serializer.serialize_str(&base64::encode(&self.serialize()))
                } else {
                    serializer.serialize_bytes(&self.serialize())
                }
            }
        }

        #[cfg(feature = "serialize")]
        #[cfg_attr(docsrs, doc(cfg(feature = "serialize")))]
        impl<'de$(, $($gen$(: $bound1$(+ $bound2)*)?),+)?> serde::Deserialize<'de> for $name$(<$($gen),+>)? {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                if deserializer.is_human_readable() {
                    let s = <&str>::deserialize(deserializer)?;
                    $name$(::<$($gen),+>)?::deserialize(&base64::decode(s).map_err(serde::de::Error::custom)?)
                        .map_err(serde::de::Error::custom)
                } else {
                    struct ByteVisitor$(<$($gen$(: $bound1$(+ $bound2)*)?),+> (
                        #[allow(unused_parens)]
                        core::marker::PhantomData<($($gen),+)>,
                    ))?;
                    impl<'de$(, $($gen$(: $bound1$(+ $bound2)*)?),+)?> serde::de::Visitor<'de> for ByteVisitor$(<$($gen),+>)? {
                        type Value = $name$(<$($gen),+>)?;
                        fn expecting(
                            &self,
                            formatter: &mut core::fmt::Formatter,
                        ) -> core::fmt::Result {
                            formatter.write_str(core::concat!(
                                "the byte representation of a ",
                                core::stringify!($name)
                            ))
                        }

                        fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                        where
                            E: serde::de::Error,
                        {
                            $name$(::<$($gen),+>)?::deserialize(value).map_err(|_| {
                                serde::de::Error::invalid_value(
                                    serde::de::Unexpected::Bytes(value),
                                    &core::concat!(
                                        "invalid byte sequence for ",
                                        core::stringify!($name)
                                    ),
                                )
                            })
                        }
                    }
                    deserializer.deserialize_bytes(ByteVisitor$(::<$($gen),+> (
                        core::marker::PhantomData,
                    ))?)
                }
            }
        }
    };
}

// Convenience macro for implementing all of the above traits
macro_rules! impl_traits_for {
    (struct $name:ident$(<$($gen:ident$(: $bound1:tt$( + $bound2:tt)*)?),+$(,)?>)?, [$(#[$pd1:ident] )?$field1:ident$(, $(#[$pd2:ident] )?$field2:ident)*$(,)?]$(, )?$([$($type:ty),+$(,)?]$(,)?)?) => {
        impl_debug_eq_hash_for!(struct $name$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)?, [$field1$(, $field2)*], $([$($type),+])?);
        impl_clone_for!(struct $name$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)?, [$field1$(, $field2)*], $([$($type),+])?);
        impl_zeroize_on_drop_for!(struct $name$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)?, [$(#[$pd1] )?$field1$(, $(#[$pd2] )?$field2)*], $([$($type),+])?);
        impl_serialize_and_deserialize_for!($name$(<$($gen$(: $bound1$(+ $bound2)*)?),+>)?);
    }
}
