use crate::enums::sid::decode_guid_le;
use ldap3::SearchEntry;
use log::trace;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
/// Represents a single attributeSchema or classSchema object from
/// CN=Schema,CN=Configuration,DC=whatever,DC=local
/// Used to build the GUID resolution map.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SchemaEntry {
    pub ldap_display_name: String,                 // lDAPDisplayName
    pub schema_id_guid: Option<[u8; 16]>,          // schemaIDGUID (from result_bin)
    pub attribute_security_guid: Option<[u8; 16]>, // attributeSecurityGUID (from result_bin)
    pub object_class: SchemaObjectClass,
    pub admin_display_name: String, // adminDisplayName
    pub dn: String,                 
}

#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub enum SchemaObjectClass {
    #[default]
    Attribute,
    Class,
}

impl SchemaEntry {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }
    pub fn parse(&mut self, result: SearchEntry) -> Result<(), Box<dyn std::error::Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;
        self.dn = result_dn;
        // Trace all result attributes
        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }
        // Trace all bin result attributes
        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }

        for (key, value) in &result_attrs {
            match key.as_str() {
                "lDAPDisplayName" => {
                    let ldap_display_name = &value[0];
                    self.ldap_display_name = ldap_display_name.to_lowercase()
                }
                "adminDisplayName" => {
                    let admin_display_name = &value[0];
                    self.admin_display_name = admin_display_name.to_lowercase().to_string()
                }
                "objectClass" => {
                    let object_class = &value[0];
                    self.object_class = if object_class.to_lowercase() == "classschema" {
                        SchemaObjectClass::Class
                    } else {
                        SchemaObjectClass::Attribute
                    }
                }
                _ => {}
            }
        }
        for (key, value) in &result_bin {
            match key.as_str() {
                "schemaIDGUID" => {
                    if let Some(guid_bytes) = value.first() {
                        self.schema_id_guid = guid_bytes.as_slice().try_into().ok();
                    }
                }
                "attributeSecurityGUID" => {
                    if let Some(guid_bytes) = value.first() {
                        self.attribute_security_guid = guid_bytes.as_slice().try_into().ok();
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

pub fn build_maps(entries: Vec<SchemaEntry>) -> (HashMap<String, String>, HashMap<String, Vec<String>>) {
    let mut schema_map = HashMap::new();
    let mut property_set_map: HashMap<String, Vec<String>> = HashMap::new();

    for entry in entries {
        if let Some(guid) = &entry.schema_id_guid {
            let guid_str = decode_guid_le(guid).to_lowercase();
            schema_map.insert(entry.admin_display_name.to_lowercase(), guid_str.clone());

            if let Some(prop_set_guid) = &entry.attribute_security_guid {
                let prop_set_str = decode_guid_le(prop_set_guid).to_lowercase();
                property_set_map.entry(prop_set_str).or_default().push(guid_str);
            }
        }
    }

    (schema_map, property_set_map)
}
