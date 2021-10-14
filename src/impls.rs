// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

/// Implement multiple similar traits at the same time. Additionally used to
/// find `#[bind]` markers to build `while` constraint.
macro_rules! impl_with_bounds {
    (
        $name:ident$(<$($gen:ident$(: $bound1:tt $(+ $bound2:tt)*)?),+>)?
        // only collect types marked with `#bind`
        // `|` prevents error about a possibly empty token
        // `@` prevents ambiguity between `$_2` and `$trait1`
        // `#` prevents ambiguity between marker traits and `$_2`
        $(|$(@#bind: $type:ty|,)? $(@#pd: $_1:ty|,)? $(@$_2:ty|,)?)+
        $trait1:path => { $($fn1:item)? },
        $($trait2:path => { $($fn2:item)? },)*
    ) => {
        impl$(<$($gen$(: $bound1 $(+ $bound2)*)?),+>)? $trait1 for $name$(<$($gen),+>)?
        where
            $($($type: $trait1,)?)+
        {
            $($fn1)?
        }

        impl_with_bounds!(
            $name$(<$($gen$(: $bound1 $(+ $bound2)*)?),+>)?
            $(|$(@#bind: $type|,)? $(@#pd: $_1|,)? $(@$_2|,)?)+
            $($trait2 => { $($fn2)? },)*
        );
    };
    // signature triggered when all traits are exhausted
    (
        $name:ident$(<$($gen:ident$(: $bound1:tt$( + $bound2:tt)*)?),+>)?
        $(|$(@#bind: $type:ty|,)? $(@#pd: $_1:ty|,)? $(@$_2:ty|,)?)+
    ) => { };
}

/// Skips attempt to call [`zeroize()`](zeroize::Zeroize::zeroize) on
/// [`PhantomData`](core::marker::PhantomData).
macro_rules! impl_internal_zeroize {
    ($self_:ident, #pd $field:ident) => {};
    ($self_:ident, #bind $field:ident) => {
        $self_.$field.zeroize();
    };
    ($self_:ident, $field:ident) => {
        $self_.$field.zeroize();
    };
}

macro_rules! impl_traits_for {
    (
        // include documentation, Rust can't connect documentation from outside
        // a macro to a `struct` generated by a macro
        $(#[doc = $doc:literal])*
        $vis:vis struct $name:ident$(<$($gen:ident$(: $bound1:tt $(+ $bound2:tt)*)?),+$(,)?>)? {
            $(#[$attr1:ident])? $vis1:vis $field1:ident: $type1:ty$(,
            $(#[$attr2:ident])? $vis2:vis $field2:ident: $type2:ty)*$(,)?
        }
    ) => {
        // build `struct` itself
        $(#[doc = $doc])*
        $vis struct $name$(<$($gen$(: $bound1 $(+$bound2)*)?),+>)? {
            $vis1 $field1: $type1,
            $($vis2 $field2: $type2),*
        }

        // implement traits that require specific `where` constraints with the
        // help of `#[bind]`
        impl_with_bounds!(
            $name$(<$($gen$(: $bound1 $(+ $bound2)*)?),+>)?
            |@$(#$attr1:)? $type1|, $(|@$(#$attr2:)? $type2|,)*
            core::fmt::Debug => {
                fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                    f.debug_struct("$name")
                    .field("$field1", &self.$field1)
                    $(.field("$field2", &self.$field2))*
                    .finish()
                }
            },
            Eq => { },
            PartialEq => {
                fn eq(&self, other: &Self) -> bool {
                    PartialEq::eq(&self.$field1, &other.$field1)
                    $(&& PartialEq::eq(&self.$field2, &other.$field2))*
                }
            },
            core::hash::Hash => {
                fn hash<_H: core::hash::Hasher>(&self, state: &mut _H) {
                    core::hash::Hash::hash(&self.$field1, state);
                    $(core::hash::Hash::hash(&self.$field2, state);)*
                }
            },
            Clone => {
                fn clone(&self) -> Self {
                    Self {
                        $field1: self.$field1.clone(),
                        $($field2: self.$field2.clone(),)*
                    }
                }
            },
        );

        impl$(<$($gen$(: $bound1 $(+ $bound2)*)?),+>)? zeroize::Zeroize for $name$(<$($gen),+>)?
        {
            fn zeroize(&mut self) {
                impl_internal_zeroize!(self, $(#$attr1)? $field1);
                $(impl_internal_zeroize!(self, $(#$attr2)? $field2);)*
            }
        }

        impl$(<$($gen$(: $bound1 $(+ $bound2)*)?),+>)? Drop for $name$(<$($gen),+>)?
        {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(self);
            }
        }

        #[cfg(feature = "serialize")]
        impl$(<$($gen$(: $bound1 $(+ $bound2)*)?),+>)? serde::Serialize for $name$(<$($gen),+>)? {
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
        impl<'de, $($($gen$(: $bound1 $(+ $bound2)*)?),+)?> serde::Deserialize<'de> for $name$(<$($gen),+>)? {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                use serde::de::Error;

                if deserializer.is_human_readable() {
                    let s = <&str>::deserialize(deserializer)?;
                    Self::deserialize(&base64::decode(s).map_err(Error::custom)?)
                } else {
                    Self::deserialize(<&[u8]>::deserialize(deserializer)?)
                }
                .map_err(Error::custom)
            }
        }
    };
}
