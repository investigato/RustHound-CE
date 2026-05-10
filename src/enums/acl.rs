// cspell:ignore OBJECTTYPE
use std::collections::HashMap;
use std::sync::OnceLock;

use crate::enums::constants::*;
use crate::enums::schema_guids::*;
use crate::enums::secdesc::*;
use crate::enums::sid::sid_maker;
use crate::objects::delegatedmsa::DelegatedMSA;
use crate::objects::{
    common::{AceTemplate, LdapObject},
    user::User,
};
use bitflags::bitflags;
use log::{error, trace};

/// This function allows to parse the attribute nTSecurityDescriptor from secdesc.rs
/// <http://www.selfadsi.org/deep-inside/ad-security-descriptors.htm#SecurityDescriptorStructure>
pub fn parse_ntsecuritydescriptor<T: LdapObject>(
    object: &mut T,
    nt: &[u8],
    entry_type: &str,
    result_attrs: &HashMap<String, Vec<String>>,
    result_bin: &HashMap<String, Vec<Vec<u8>>>,
    domain: &str,
) -> Vec<AceTemplate> {
    let mut relations_dacl: Vec<AceTemplate> = Vec::new();
    let relations_sacl: Vec<AceTemplate> = Vec::new();
    let mut owner_sid: String = "".to_string();

    let secdesc: SecurityDescriptor = SecurityDescriptor::parse(nt).unwrap().1;
    trace!("SECURITY-DESCRIPTOR: {:?}", secdesc);

    // Check for ACL protected for Bloodhound4.1+
    // IsACLProtected
    let acl_is_protected = has_control(secdesc.control, SecurityDescriptorFlags::DACL_PROTECTED);
    //trace!("{} acl_is_protected: {:?}",object.properties().name,acl_is_protected);

    match entry_type {
        "EnterpriseCA" | "RootCA" | "CertTemplate" => {
            object.set_is_acl_protected(acl_is_protected);
        }
        _ => {}
    }

    if secdesc.offset_owner as usize != 0 {
        owner_sid = sid_maker(
            LdapSid::parse(&nt[secdesc.offset_owner as usize..])
                .unwrap()
                .1,
            domain,
        );
        trace!("OWNER-SID: {:?}", owner_sid);
    }

    if secdesc.offset_group as usize != 0 {
        let group_sid = sid_maker(
            LdapSid::parse(&nt[secdesc.offset_group as usize..])
                .unwrap()
                .1,
            domain,
        );
        trace!("GROUP-SID: {:?}", group_sid);
    }

    if secdesc.offset_sacl as usize != 0 {
        let res = Acl::parse(&nt[secdesc.offset_sacl as usize..]);
        match res {
            Ok(_res) => {
                let sacl = _res.1;
                trace!("SACL: {:?}", sacl);
                //let aces = sacl.data;
                /*ace_maker(
                    object,
                    domain,
                    &mut relations_sacl,
                    &owner_sid,
                    aces,
                    &entry_type,
                    result_attrs,
                    result_bin,
                );*/
                trace!("RESULT: {:?}", relations_sacl);
            }
            Err(err) => error!("Error. Reason: {err}"),
        }
        return relations_sacl;
    }

    if secdesc.offset_dacl as usize != 0 {
        let res = Acl::parse(&nt[secdesc.offset_dacl as usize..]);
        match res {
            Ok(_res) => {
                let dacl = _res.1;
                trace!("DACL: {:?}", dacl);
                let aces = dacl.data;
                ace_maker(
                    object,
                    domain,
                    &mut relations_dacl,
                    &owner_sid,
                    aces,
                    entry_type,
                    result_attrs,
                    result_bin,
                );
                trace!("RESULT: {:?}", relations_dacl);
            }
            Err(err) => error!("Error. Reason: {err}"),
        }
        return relations_dacl;
    }
    relations_dacl
}

/// Parse ace in acl and get correct values (thanks fox-it for bloodhound.py works)
/// <https://github.com/fox-it/BloodHound.py/blob/master/bloodhound/enumeration/acls.py>
fn ace_maker<T: LdapObject>(
    object: &mut T,
    domain: &str,
    relations: &mut Vec<AceTemplate>,
    osid: &str,
    aces: Vec<Ace>,
    entry_type: &str,
    _result_attrs: &HashMap<String, Vec<String>>,
    _result_bin: &HashMap<String, Vec<Vec<u8>>>,
) {
    // trace!("ACL/ACE FOR ENTRY: {:?}",object.properties().name);
    // Ignore Creator Owner or Local System
    const IGNORE_SIDS: &[&str] = &["S-1-3-0", "S-1-5-18", "S-1-5-10"];
    //, "S-1-1-0".to_string(), "S-1-5-10".to_string(), "S-1-5-11".to_string()];
    if IGNORE_SIDS.iter().any(|i| !osid.contains(i)) {
        relations.push(AceTemplate::new(
            osid.to_owned(),
            "Base".to_string(),
            "Owns".to_string(),
            false,
            "".to_string(),
        ));
    }

    for ace in aces {
        if ace.ace_type != 0x05 && ace.ace_type != 0x00 {
            trace!("Don't care about acetype {:?}", ace.ace_type);
            continue;
        }

        let sid = sid_maker(AceFormat::get_sid(ace.data.to_owned()).unwrap(), domain);
        trace!("SID for this ACE: {}", &sid);

        // Check if sid is in the ignored list
        if IGNORE_SIDS.iter().any(|i| sid.contains(i)) {
            continue;
        }

        // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L74
        if ace.ace_type == 0x05 {
            trace!("TYPE: 0x05");
            // GUID : inherited_object_type
            let inherited_object_type =
                AceFormat::get_inherited_object_type(&ace.data).unwrap_or_default();
            // GUID : object_type
            let object_type = AceFormat::get_object_type(&ace.data).unwrap_or_default();
            // Get and check ace.ace_flags object content INHERITED_ACE and return boolean
            let is_inherited = ace.ace_flags & INHERITED_ACE == INHERITED_ACE;
            // Get the Flag for the ace.datas
            let flags = AceFormat::get_flags(&ace.data).unwrap().bits();

            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L77
            if (ace.ace_flags & INHERITED_ACE != INHERITED_ACE)
                && (ace.ace_flags & INHERIT_ONLY_ACE == INHERIT_ONLY_ACE)
            {
                // ACE is set on this object, but only inherited, so not applicable to us
                continue;
            }

            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L82
            if (ace.ace_flags & INHERITED_ACE == INHERITED_ACE)
                && (flags & ACE_INHERITED_OBJECT_TYPE_PRESENT == ACE_INHERITED_OBJECT_TYPE_PRESENT)
            {
                // ACE is set on this object, but only inherited, so not applicable to us
                // need to verify if the ACE applies to this object type #todo
                // Verify if the ACE applies to this object type
                // if not ace_applies(ace_object.acedata.get_inherited_object_type().lower(), entrytype, objecttype_guid_map):
                // continue
                // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L85
                let ace_guid = inherited_object_type;
                if !ace_applies(&ace_guid, entry_type) {
                    continue;
                }
            }

            let mask = match AceFormat::get_mask(&ace.data) {
                Some(mask) => mask,
                None => continue,
            };
            trace!("ACE MASK for ACETYPE 0x05: {:?}", mask);

            let ace_guid = object_type;
            trace!("ACE GUID for ACETYPE 0x05: {:?}", ace_guid);

            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L92
            if ((MaskFlags::GENERIC_ALL.bits() | mask) == mask)
                || ((MaskFlags::WRITE_DACL.bits() | mask) == mask)
                || ((MaskFlags::WRITE_OWNER.bits() | mask) == mask)
                || ((MaskFlags::GENERIC_WRITE.bits() | mask) == mask)
            {
                trace!(
                    "ACE MASK contain: GENERIC_ALL or WRITE_DACL or WRITE_OWNER or GENERIC_WRITE"
                );
                let inherited_ace_guid = inherited_object_type;
                if flags & ACE_INHERITED_OBJECT_TYPE_PRESENT == ACE_INHERITED_OBJECT_TYPE_PRESENT
                    && !ace_applies(&inherited_ace_guid, entry_type)
                {
                    continue;
                }
                if (MaskFlags::GENERIC_ALL.bits() | mask) == mask {
                    if entry_type == "Computer"
                        && (flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                        && object.get_haslaps().to_owned()
                        && get_schema_map()
                            .get("ms-mcs-admpwd")
                            .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                            .unwrap_or(false)
                    {
                        relations.push(AceTemplate::new(
                            sid.to_owned(),
                            "".to_string(),
                            "ReadLAPSPassword".to_string(),
                            is_inherited,
                            "".to_string(),
                        ));
                    } else {
                        relations.push(AceTemplate::new(
                            sid.to_owned(),
                            "".to_string(),
                            "GenericAll".to_string(),
                            is_inherited,
                            "".to_string(),
                        ));
                    }
                    continue;
                }
                if (MaskFlags::GENERIC_WRITE.bits() | mask) == mask {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GenericWrite".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                    if (entry_type != "Domain") && (entry_type != "Computer") {
                        continue;
                    }
                }
                if (MaskFlags::WRITE_DACL.bits() | mask) == mask {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteDacl".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if (MaskFlags::WRITE_OWNER.bits() | mask) == mask {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteOwner".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
            }

            // Property write privileges
            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L126
            if (MaskFlags::ADS_RIGHT_DS_WRITE_PROP.bits() | mask) == mask {
                if ((entry_type == "User")
                    || (entry_type == "Group")
                    || (entry_type == "Computer")
                    || (entry_type == "Gpo")
                    || (entry_type == "OU"))
                    && (flags & ACE_OBJECT_TYPE_PRESENT != ACE_OBJECT_TYPE_PRESENT)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GenericWrite".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if entry_type == "Group" && can_write_property(&ace, "member") {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        // "AddMember".to_string(),
                        "AddOrRemoveMember".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }

                if ["User", "Computer", "Group"].contains(&entry_type)
                    && !is_filtered_sid(&sid)
                    && get_schema_map()
                        .get("name")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteRDN".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["User", "Computer", "Group"].contains(&entry_type)
                    && !is_filtered_sid(&sid)
                    && get_schema_map()
                        .get("cn")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteCommonName".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["User", "Computer", "Group"].contains(&entry_type)
                    && !is_filtered_sid(&sid)
                    && get_schema_map()
                        .get("user-account-control")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteUserAccountControl".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["User", "Computer", "Group"].contains(&entry_type)
                    && !is_filtered_sid(&sid)
                    && get_schema_map()
                        .get("ms-ds-managed-account-preceded-by-link")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteMsDSManagedAccountPrecededByLink".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["User", "Computer", "Group"].contains(&entry_type)
                    && !is_filtered_sid(&sid)
                    && get_schema_map()
                        .get("ms-ds-superseded-managed-account-link")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteMsDSSupersededManagedAccountLink".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["User", "Computer", "Group"].contains(&entry_type)
                    && !is_filtered_sid(&sid)
                    && get_schema_map()
                        .get("ms-ds-superseded-service-account-state")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteMsDSSupersededServiceAccountState".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["User", "Computer", "Group"].contains(&entry_type)
                    && !is_filtered_sid(&sid)
                    && get_schema_map()
                        .get("ms-ds-delegated-msa-state")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteMsDSDelegatedMSAState".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["User", "Computer", "Group"].contains(&entry_type)
                    && !is_filtered_sid(&sid)
                    && get_schema_map()
                        .get("ms-ds-group-msa-membership")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteMsDSGroupMSAMembership".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if entry_type == "Group"
                    && (&ace_guid
                        == match PROPERTY_SET_GUID_MAP.get(USER_ACCOUNT_RESTRICTIONS_SET) {
                            Some(guid) => guid,
                            None => return,
                        })
                    && sid.ends_with("-512")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteAccountRestrictions".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if entry_type == "Computer"
                    && can_write_property(&ace, "msds-allowedtoactonbehalfofotheridentity")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AddAllowedToAct".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if entry_type == "Computer"
                    && (&ace_guid
                        == match PROPERTY_SET_GUID_MAP.get(USER_ACCOUNT_RESTRICTIONS_SET) {
                            Some(guid) => guid,
                            None => return,
                        })
                    && !sid.ends_with("-512")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteAccountRestrictions".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if entry_type == "OU" && can_write_property(&ace, "gplink") {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteGPLink".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                // Since BloodHound 4.1
                // AddKeyCredentialLink write access
                if ((entry_type == "User") || (entry_type == "Computer"))
                    && (flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                    && get_schema_map()
                        .get("ms-ds-key-credential-link")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AddKeyCredentialLink".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ((entry_type == "User") || (entry_type == "Computer"))
                    && (flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                    && get_schema_map()
                        .get("service-principal-name")
                        .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                        .unwrap_or(false)
                    || PROPERTY_SET_GUID_MAP.get("public-information") == Some(&ace_guid)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "WriteSPN".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
            } else if (MaskFlags::ADS_RIGHT_DS_SELF.bits() | mask) == mask
                && (entry_type == "Group")
                && get_schema_map()
                    .get("member")
                    .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                    .unwrap_or(false)
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "AddSelf".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }

            // Property read privileges
            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L138
            if (MaskFlags::ADS_RIGHT_DS_READ_PROP.bits() | mask) == mask
                && (entry_type == "Computer")
                && (flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
                && object.get_haslaps().to_owned()
                && get_schema_map()
                    .get("ms-mcs-admpwd")
                    .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                    .unwrap_or(false)
                || get_schema_map()
                    .get("ms-laps-password")
                    .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                    .unwrap_or(false)
                || get_schema_map()
                    .get("ms-laps-encryptedpassword")
                    .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                    .unwrap_or(false)
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "ReadLAPSPassword".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }
            if ["User", "Group", "OU", "Computer"].contains(&entry_type)
                && (MaskFlags::ADS_RIGHT_DS_CREATE_CHILD.bits() | mask) == mask
                && !is_filtered_sid(&sid)
                && (flags & ACE_OBJECT_TYPE_PRESENT == ACE_OBJECT_TYPE_PRESENT)
            {
                if get_schema_map()
                    .get("ms-ds-delegated-managed-service-account")
                    .map(|bytes| u128::from_le_bytes(*bytes) == ace_guid)
                    .unwrap_or(false)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "CreateChildDMSA".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                } else {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "CreateChild".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
            }
            // Extended rights
            // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L146
            if (MaskFlags::ADS_RIGHT_DS_CONTROL_ACCESS.bits() | mask) == mask {
                // All Extended
                if ["User", "Domain"].contains(&entry_type)
                    && (flags & ACE_OBJECT_TYPE_PRESENT != ACE_OBJECT_TYPE_PRESENT)
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AllExtendedRights".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if (entry_type == "Computer")
                    && (flags & ACE_OBJECT_TYPE_PRESENT != ACE_OBJECT_TYPE_PRESENT)
                // && false
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AllExtendedRights".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if (entry_type == "Domain")
                    && has_extended_right(&ace, "ds-replication-get-changes")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GetChanges".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if (entry_type == "Domain")
                    && has_extended_right(&ace, "ds-replication-get-changes-all")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GetChangesAll".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if (entry_type == "Domain")
                    && has_extended_right(&ace, "ds-replication-get-changes-in-filtered-set")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "GetChangesInFilteredSet".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                // if (entry_type == "User")
                //     && has_extended_right(&ace, USER_CHANGE_PASSWORD)
                // {
                //     relations.push(AceTemplate::new(
                //         sid.to_owned(),
                //         "".to_string(),
                //         "ForceChangePassword".to_string(), // Maybe need to be change if is not "Force"
                //         is_inherited,
                //         "".to_string(),
                //     ));
                // }
                if ["User", "Computer", "Group"].contains(&entry_type)
                    && has_extended_right(&ace, "user-force-change-password")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "ForceChangePassword".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["User", "Group", "OU", "Computer", "Domain"].contains(&entry_type)
                    && has_extended_right(&ace, "reanimate-tombstones")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "ReanimateTombstones".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }

                if ["EnterpriseCA", "RootCA", "CertTemplate"].contains(&entry_type)
                    && has_extended_right(&ace, "certificate-enrollment")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "Enroll".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
                if ["EnterpriseCA", "RootCA", "CertTemplate"].contains(&entry_type)
                    && has_extended_right(&ace, "certificate-autoenrollment")
                {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AutoEnroll".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
            }
        }

        // For AceType == 0x00
        // https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L162
        if ace.ace_type == 0x00 {
            trace!("TYPE: 0x00");

            let is_inherited = ace.ace_flags & INHERITED_ACE == INHERITED_ACE;

            let mask = match AceFormat::get_mask(&ace.data) {
                Some(mask) => mask,
                None => continue,
            };

            trace!("ACE MASK for ACETYPE 0x00: {:?}", mask);

            if (MaskFlags::GENERIC_ALL.bits() | mask) == mask {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "GenericAll".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
                continue;
            }
            if (MaskFlags::ADS_RIGHT_DS_WRITE_PROP.bits() | mask) == mask {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "GenericWrite".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }
            if (MaskFlags::WRITE_OWNER.bits() | mask) == mask {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "WriteOwner".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }
            // For users and domain, check extended rights
            if ((entry_type == "User") || (entry_type == "Domain"))
                && ((MaskFlags::ADS_RIGHT_DS_CONTROL_ACCESS.bits() | mask) == mask)
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "AllExtendedRights".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }
            // For computer
            if (entry_type == "Computer")
                && ((MaskFlags::ADS_RIGHT_DS_CONTROL_ACCESS.bits() | mask) == mask)
            // && false
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "AllExtendedRights".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }
            if (MaskFlags::WRITE_DACL.bits() | mask) == mask {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "WriteDacl".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }
            // Self add, also possible ad ACCESS_ALLOWED_ACE
            // Thanks to bh-py: <https://github.com/dirkjanm/BloodHound.py/blob/d47e765fd3d0356e2e4b48d0d9a0841525194c64/bloodhound/enumeration/acls.py#L221C1-L225C97>
            if (MaskFlags::ADS_RIGHT_DS_SELF.bits() & mask) == mask && !is_filtered_sid(&sid) {
                if entry_type == "Group" {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "AddSelf".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                } else {
                    relations.push(AceTemplate::new(
                        sid.to_owned(),
                        "".to_string(),
                        "Self".to_string(),
                        is_inherited,
                        "".to_string(),
                    ));
                }
            }
            if ["User", "Group", "OU", "Computer"].contains(&entry_type)
                && (MaskFlags::ADS_RIGHT_DS_CREATE_CHILD.bits() | mask) == mask
                && !is_filtered_sid(&sid)
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "CreateChildAll".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }

            if ["EnterpriseCA"].contains(&entry_type) // "RootCA"
                && (MaskFlags::MANAGE_CA.bits() | mask) == mask
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "ManageCA".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }
            if ["EnterpriseCA", "RootCA"].contains(&entry_type)
                && (MaskFlags::MANAGE_CERTIFICATES.bits() | mask) == mask
            {
                relations.push(AceTemplate::new(
                    sid.to_owned(),
                    "".to_string(),
                    "ManageCertificates".to_string(),
                    is_inherited,
                    "".to_string(),
                ));
            }
        }
    }
}

/// Checks if the access is sufficient to write to a specific property.
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L193>
fn can_write_property(ace: &Ace, right_name: &str) -> bool {
    // This can either be because we have the right ADS_RIGHT_DS_WRITE_PROP and the correct GUID
    // is set in ObjectType, or if we have the ADS_RIGHT_DS_WRITE_PROP right and the ObjectType
    // is empty, in which case we can write to any property. This is documented in
    // [MS-ADTS] section 5.1.3.2: https://msdn.microsoft.com/en-us/library/cc223511.aspx
    let right_guid_bytes = match get_schema_map().get(right_name) {
        Some(bytes) => bytes,
        None => {
            error!("has_write_property: unknown right name '{}'", right_name);
            return false;
        }
    };
    // If not found, then assume can't write. Should not happen, but missing some parsers.
    let mask = match AceFormat::get_mask(&ace.data) {
        Some(mask) => mask,
        None => return false,
    };

    if (MaskFlags::ADS_RIGHT_DS_WRITE_PROP.bits() | mask) != mask {
        //if not ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP):
        return false;
    }

    // Get the Flag for the ace.datas
    let flags = AceFormat::get_flags(&ace.data).unwrap().bits();

    if (flags & ACE_OBJECT_TYPE_PRESENT) != ACE_OBJECT_TYPE_PRESENT {
        return true;
    }

    let object_type = AceFormat::get_object_type(&ace.data).unwrap_or_default();

    u128::from_le_bytes(*right_guid_bytes) == object_type
}

/// Checks if the access is sufficient to control the right with the given GUID.
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L211>
fn has_extended_right(ace: &Ace, right_name: &str) -> bool {
    // This can either be because we have the right ADS_RIGHT_DS_CONTROL_ACCESS and the correct GUID
    // is set in ObjectType, or if we have the ADS_RIGHT_DS_CONTROL_ACCESS right and the ObjectType
    // is empty, in which case we have all extended rights. This is documented in
    // [MS-ADTS] section 5.1.3.2: https://msdn.microsoft.com/en-us/library/cc223511.aspx
    let right_guid_bytes = match EXTENDED_RIGHTS_GUID_MAP.get(right_name) {
        Some(guid) => guid,
        None => {
            error!("has_extended_right: unknown right name '{}'", right_name);
            return false;
        }
    };
    let mask = match AceFormat::get_mask(&ace.data) {
        Some(mask) => mask,
        None => return false,
    };
    if (MaskFlags::ADS_RIGHT_DS_CONTROL_ACCESS.bits() | mask) != mask {
        // if not ace_object.acedata.mask.has_priv(ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS):
        trace!("has_extended_right : return false for ADS_RIGHT_DS_CONTROL_ACCESS != mask");
        return false;
    }
    // Get the Flag for the ace.datas
    let flags = AceFormat::get_flags(&ace.data).unwrap().bits();
    if (flags & ACE_OBJECT_TYPE_PRESENT) != ACE_OBJECT_TYPE_PRESENT {
        return true;
    }
    let result = AceFormat::get_object_type(&ace.data).unwrap_or_default() == *right_guid_bytes;
    trace!("has_extended_right : result = {:?}", result);
    result
}

/// Check if an ACE applies to this object.
/// <https://github.com/fox-it/BloodHound.py/blob/645082e3462c93f31b571db945cde1fd7b837fb9/bloodhound/enumeration/acls.py#L229>
fn ace_applies(ace_guid: &u128, entry_type: &str) -> bool {
    // Checks if an ACE applies to this object (based on object classes).
    // Note that this function assumes you already verified that InheritedObjectType is set (via the flag).
    // If this is not set, the ACE applies to all object types.
    trace!("ACE GUID: {}", &ace_guid);
    let entry_type_lower = entry_type.to_lowercase();
    trace!(
        "get_schema_map(): {}",
        get_schema_map()
            .get(&entry_type_lower)
            .map(|bytes| u128::from_le_bytes(*bytes) == *ace_guid)
            .unwrap_or(false)
    );
    get_schema_map()
        .get(&entry_type_lower)
        .map(|bytes| u128::from_le_bytes(*bytes) == *ace_guid)
        .unwrap_or(false)
}

/// Function to parse GMSA DACL which states which users (or groups) can read the password
pub fn parse_gmsa(processed_aces: &[AceTemplate], user: &mut User) {
    for ace in processed_aces {
        if ace.right_name() == "Owner" {
            // || ace.right_name() == "Owns" {
            continue;
        }
        let mut ace = ace.clone();
        *ace.right_name_mut() = "ReadGMSAPassword".to_string();
        user.aces_mut().push(ace);
    }
}

/// Function to parse GMSA DACL which states which users (or groups) can read the password
pub fn parse_gmsa_dmsa(processed_aces: &[AceTemplate], dmsa: &mut DelegatedMSA) {
    for ace in processed_aces {
        if ace.right_name() == "Owner" {
            // || ace.right_name() == "Owns" {
            continue;
        }
        let mut ace = ace.clone();
        *ace.right_name_mut() = "ReadGMSAPassword".to_string();
        dmsa.aces_mut().push(ace);
    }
}

/// Function to get relations for CASecurity from LDAP attribute.
pub fn parse_ca_security(
    nt: &[u8],
    hosting_computer_sid: &String,
    domain: &str,
) -> Vec<AceTemplate> {
    // The CASecurity exist in the AD object DACL and in registry of the CA server.
    // SharpHound prefer to use the values from registry as they are the ground truth.
    // If changes are made on the CA server, registry and the AD object is updated.
    // If changes are made directly on the AD object, the CA server registry is not updated.
    // For RustHound, we need to use AD object DACL because we don't have RPC to read registry yet.
    let blacklist_sid = [
        // <https://learn.microsoft.com/fr-fr/windows-server/identity/ad-ds/manage/understand-security-identifiers>
        "-544", // Administrators
        "-519", // Enterprise Administrators
        "-512", // Domain Admins
    ];
    let mut relations: Vec<AceTemplate> = Vec::new();
    // Hosting Computer local administrator group is the owner.
    relations.push(AceTemplate::new(
        hosting_computer_sid.to_owned() + "-544",
        "LocalGroup".to_string(),
        "Owns".to_string(),
        false,
        "".to_string(),
    ));
    let secdesc: SecurityDescriptor = SecurityDescriptor::parse(nt).unwrap().1;
    if secdesc.offset_dacl as usize != 0 {
        let res = Acl::parse(&nt[secdesc.offset_dacl as usize..]);
        match res {
            Ok(_res) => {
                let dacl = _res.1;
                let aces = dacl.data;
                for ace in aces {
                    let sid = sid_maker(AceFormat::get_sid(ace.data.to_owned()).unwrap(), domain);
                    let mask = match AceFormat::get_mask(&ace.data) {
                        Some(mask) => mask,
                        None => continue,
                    };
                    if ace.ace_type == 0x05 && has_extended_right(&ace, "certificate-enrollment") {
                        relations.push(AceTemplate::new(
                            sid.to_owned(),
                            "".to_string(),
                            "Enroll".to_string(),
                            false,
                            "".to_string(),
                        ));
                    }
                    if ace.ace_type == 0x00 {
                        if (MaskFlags::MANAGE_CERTIFICATES.bits() | mask) == mask {
                            // trace!("SID: {:?}\nMASK: ManageCertificates",&sid);
                            if !blacklist_sid
                                .iter()
                                .any(|blacklisted| sid.ends_with(blacklisted))
                            {
                                // HostingComputer SID, need to add -544 for LocalGroup
                                relations.push(AceTemplate::new(
                                    sid.to_owned() + "-544",
                                    "LocalGroup".to_string(),
                                    "ManageCertificates".to_string(),
                                    false,
                                    "".to_string(),
                                ));
                            } else {
                                relations.push(AceTemplate::new(
                                    sid.to_owned(),
                                    "Group".to_string(),
                                    "ManageCertificates".to_string(),
                                    false,
                                    "".to_string(),
                                ));
                            }
                        }
                        if (MaskFlags::MANAGE_CA.bits() | mask) == mask {
                            // trace!("SID: {:?}\nMASK: ManageCA",&sid);
                            if !blacklist_sid
                                .iter()
                                .any(|blacklisted| sid.ends_with(blacklisted))
                            {
                                // HostingComputer SID, need to add -544 for LocalGroup
                                relations.push(AceTemplate::new(
                                    sid.to_owned() + "-544",
                                    "LocalGroup".to_string(),
                                    "ManageCA".to_string(),
                                    false,
                                    "".to_string(),
                                ));
                            } else {
                                relations.push(AceTemplate::new(
                                    sid.to_owned(),
                                    "Group".to_string(),
                                    "ManageCA".to_string(),
                                    false,
                                    "".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
            Err(err) => error!("Error. Reason: {err}"),
        }
    }
    relations
}

// Access Mask contain value?
bitflags! {
    pub struct MaskFlags: u32 {
        // These constants are only used when WRITING
        // and are then translated into their actual rights
        const SET_GENERIC_READ        = 0x80000000;
        const SET_GENERIC_WRITE       = 0x04000000;
        const SET_GENERIC_EXECUTE     = 0x20000000;
        const SET_GENERIC_ALL         = 0x10000000;
        // When reading, these constants are actually represented by
        // the following for Active Directory specific Access Masks
        // Reference: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2
        const GENERIC_READ            = 0x00020094;
        const GENERIC_WRITE           = 0x00020028;
        const GENERIC_EXECUTE         = 0x00020004;
        const GENERIC_ALL             = 0x000F01FF;

        // These are actual rights (for all ACE types)
        const MAXIMUM_ALLOWED         = 0x02000000;
        const ACCESS_SYSTEM_SECURITY  = 0x01000000;
        const SYNCHRONIZE             = 0x00100000;
        const WRITE_OWNER             = 0x00080000;
        const WRITE_DACL              = 0x00040000;
        const READ_CONTROL            = 0x00020000;
        const DELETE                  = 0x00010000;

        // ACE type specific mask constants (for ACCESS_ALLOWED_OBJECT_ACE)
        // Note that while not documented, these also seem valid
        // for ACCESS_ALLOWED_ACE types
        const ADS_RIGHT_DS_CONTROL_ACCESS         = 0x00000100;
        const ADS_RIGHT_DS_CREATE_CHILD           = 0x00000001;
        const ADS_RIGHT_DS_DELETE_CHILD           = 0x00000002;
        const ADS_RIGHT_DS_READ_PROP              = 0x00000010;
        const ADS_RIGHT_DS_WRITE_PROP             = 0x00000020;
        const ADS_RIGHT_DS_SELF                   = 0x00000008;

        // ADCS
        const MANAGE_CA = 1;
        const MANAGE_CERTIFICATES = 2;
    }
}

bitflags! {
    struct SecurityDescriptorFlags: u16 {
        const SELF_RELATIVE = 0b1000000000000000;
        const RM_CONTROL_VALID = 0b0100000000000000;
        const SACL_PROTECTED = 0b0010000000000000;
        const DACL_PROTECTED = 0b0001000000000000;
        const SACL_INHERITED = 0b0000100000000000;
        const DACL_INHERITED = 0b0000010000000000;
        const SACL_COMPUTED_INHERITANCE_REQUIRED = 0b0000001000000000;
        const DACL_COMPUTED_INHERITANCE_REQUIRED = 0b0000000100000000;
        const SERVER_SECURITY = 0b0000000010000000;
        const DACL_TRUSTED = 0b0000000001000000;
        const SACL_DEFAULT = 0b0000000000100000;
        const SACL_PRESENT = 0b0000000000010000;
        const DACL_DEFAULT = 0b0000000000001000;
        const DACL_PRESENT = 0b0000000000000100;
        const GROUP_DEFAULT = 0b0000000000000010;
        const OWNER_DEFAULT = 0b0000000000000001;
    }
}

fn has_control(secdesc_control: u16, flag: SecurityDescriptorFlags) -> bool {
    let flags = SecurityDescriptorFlags::from_bits(secdesc_control).unwrap();
    flags.contains(flag)
}
static SCHEMA_GUID_MAP: OnceLock<HashMap<String, [u8; 16]>> = OnceLock::new();
static PROPERTY_SET_CHILD_MAP: OnceLock<HashMap<[u8; 16], Vec<[u8; 16]>>> = OnceLock::new();
pub fn init_maps(
    schema: HashMap<String, [u8; 16]>,
    property_set: HashMap<[u8; 16], Vec<[u8; 16]>>,
) {
    let mut base_attributes = build_default_guid_map();
    base_attributes.extend(schema);
    let _ = SCHEMA_GUID_MAP.set(base_attributes);
    let _ = PROPERTY_SET_CHILD_MAP.set(property_set);
}

// fn get_property_set_child_map() -> &'static HashMap<String, Vec<String>> {
//     PROPERTY_SET_CHILD_MAP.get_or_init(|| HashMap::new())
// }
pub fn get_schema_map() -> &'static HashMap<String, [u8; 16]> {
    SCHEMA_GUID_MAP.get_or_init(build_default_guid_map)
}
fn is_filtered_sid(sid: &str) -> bool {
    sid.ends_with("S-1-5-18")               // SYSTEM
        || sid.ends_with("S-1-5-32-544")    // BUILTIN\Administrators
        || sid.ends_with("S-1-5-32-548")    // Account Operators
        || sid.ends_with("S-1-5-32-549")    // Server Operators
        || sid.ends_with("S-1-5-32-550")    // Print Operators
        || sid.ends_with("S-1-5-32-551")    // Backup Operators
        || sid.ends_with("-500")            // Administrator
        || sid.ends_with("-502")            // krbtgt
        || sid.ends_with("-512")            // Domain Admins
        || sid.ends_with("-516")            // Domain Controllers
        || sid.ends_with("-518")            // Schema Admins
        || sid.ends_with("-519")            // Enterprise Admins
        || sid.ends_with("-520")            // Group Policy Creator Owners
        || sid.ends_with("-521") // RODCs
}
