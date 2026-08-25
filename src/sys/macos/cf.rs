//! CoreFoundation → owned Rust values.
//!
//! Every SCDynamicStore read in this backend goes through here, so the rest of
//! the macOS code works over plain Rust types. Keeping the CF handling in one
//! place is also what stops a `CFTypeRef` from leaking out through the
//! `Platform` trait.

use std::collections::BTreeMap;

use system_configuration::core_foundation::array::CFArray;
use system_configuration::core_foundation::base::{CFType, TCFType};
use system_configuration::core_foundation::boolean::CFBoolean;
use system_configuration::core_foundation::data::CFData;
use system_configuration::core_foundation::dictionary::CFDictionary;
use system_configuration::core_foundation::number::CFNumber;
use system_configuration::core_foundation::string::CFString;
use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};

/// An owned, borrowed-nothing view of a property list value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Dict(BTreeMap<String, Value>),
    Array(Vec<Value>),
    Str(String),
    Int(i64),
    Real(f64),
    Bool(bool),
    Data(Vec<u8>),
    /// A type we do not model. Present so a dictionary walk never silently
    /// drops a key.
    Opaque,
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Real(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            Value::Data(d) => Some(d),
            _ => None,
        }
    }

    /// Look up a key in a dictionary value. `None` for any other kind.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Dict(map) => map.get(key),
            _ => None,
        }
    }

    /// The elements of an array value, or an empty slice.
    pub fn items(&self) -> &[Value] {
        match self {
            Value::Array(v) => v,
            _ => &[],
        }
    }

    /// An array of strings, skipping anything that is not one.
    pub fn string_list(&self) -> Vec<String> {
        self.items()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    }
}

/// Open a read-only session against the dynamic store.
pub fn open_store() -> Option<SCDynamicStore> {
    SCDynamicStoreBuilder::new("netinspect").build()
}

/// Read one key. Returns `None` when the key is absent — which on macOS 15+ is
/// the normal answer for several keys the older docs still describe.
pub fn read(store: &SCDynamicStore, key: &str) -> Option<Value> {
    let raw = store.get(CFString::new(key))?;
    Some(convert(&raw.as_CFType()))
}

/// List the keys matching a pattern.
pub fn read_keys(store: &SCDynamicStore, pattern: &str) -> Vec<String> {
    match store.get_keys(CFString::new(pattern)) {
        Some(array) => array.iter().map(|k| k.to_string()).collect(),
        None => Vec::new(),
    }
}

fn convert(value: &CFType) -> Value {
    if let Some(s) = value.downcast::<CFString>() {
        return Value::Str(s.to_string());
    }
    if let Some(b) = value.downcast::<CFBoolean>() {
        return Value::Bool(b == CFBoolean::true_value());
    }
    if let Some(n) = value.downcast::<CFNumber>() {
        // Integers are the common case; fall back to a float so a real number
        // is not lost.
        return match n.to_i64() {
            Some(i) => Value::Int(i),
            None => n.to_f64().map(Value::Real).unwrap_or(Value::Opaque),
        };
    }
    if let Some(d) = value.downcast::<CFData>() {
        return Value::Data(d.bytes().to_vec());
    }
    if let Some(a) = value.downcast::<CFArray>() {
        let items = a
            .get_all_values()
            .into_iter()
            // Safety: the pointers come out of the array we are still holding,
            // and get-rule wrapping does not take ownership.
            .map(|p| convert(&unsafe { CFType::wrap_under_get_rule(p.cast()) }))
            .collect();
        return Value::Array(items);
    }
    if let Some(d) = value.downcast::<CFDictionary>() {
        let (keys, values) = d.get_keys_and_values();
        let mut map = BTreeMap::new();
        for (k, v) in keys.into_iter().zip(values) {
            // Safety: the pointers come straight out of the dictionary we are
            // holding, so they are valid for at least this scope, and
            // get-rule wrapping does not take ownership.
            let key = unsafe { CFString::wrap_under_get_rule(k.cast()) }.to_string();
            let val = unsafe { CFType::wrap_under_get_rule(v.cast()) };
            map.insert(key, convert(&val));
        }
        return Value::Dict(map);
    }
    Value::Opaque
}
