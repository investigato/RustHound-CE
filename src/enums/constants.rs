pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
pub const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;

pub const CONTAINER_INHERIT_ACE: u8 = 0x01;
pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
pub const INHERIT_ONLY_ACE: u8 = 0x08;
pub const INHERITED_ACE: u8 = 0x10;
pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
pub const OBJECT_INHERIT_ACE: u8 = 0x01;
pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x04;

pub const ACE_OBJECT_TYPE_PRESENT: u32 = 0x0001;
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x0002;

// EXTRIGHTS_GUID_MAPPING
pub const GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
pub const GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
pub const GET_CHANGES_IN_FILTERED_SET: &str = "89e95b76-444d-4c62-991a-0facbeda640c";
pub const WRITE_MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
pub const REANIMATE_TOMBSTONES: &str = "45ec5156-db7e-47bb-b53f-dbeb2d03c40f";
// pub const USER_CHANGE_PASSWORD: &str = "ab721a53-1e2f-11d0-9819-00aa0040529b";
pub const USER_FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
pub const ALLOWED_TO_ACT: &str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
pub const USER_ACCOUNT_RESTRICTIONS_SET: &str = "4c164200-20c0-11d0-a768-00aa006e0529";
pub const WRITE_GPLINK: &str = "f30e3bbe-9ff0-11d1-b603-0000f80367c1";
pub const WRITE_SPN: &str = "f3a64788-5306-11d1-a9c5-0000f80367c1";
pub const ADD_KEY_PRINCIPAL: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";
// ADCS
pub const PKI_NAME_FLAG: &str = "ea1dddc4-60ff-416e-8cc0-17cee534bce7";
pub const PKI_ENROLLMENT_FLAG: &str = "d15ef7d8-f226-46db-ae79-b34e560bd12c";
pub const ENROLL: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
pub const AUTO_ENROLL: &str = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";
pub static EXTENDED_RIGHTS_GUID_MAP: phf::Map<&str, u128> = phf::phf_map! {
 "abandon-replication"=>0xcdd5d84fc000bbad11d10a98ee914b82_u128,
"add-guid"=>0x0dae75f80000daa311d165b4440820ad_u128,
"allocate-rids"=>0xcdd5d84fc000bbad11d10a991abd7cf8_u128,
"allowed-to-authenticate"=>0xbca7792e154671ab4d4f0d1568b1d179_u128,
"apply-group-policy"=>0x39f968c9a0001db411d1ffb3edacfd8f_u128,
"certificate-enrollment"=>0x55dc794fc000d49011d278fb0e10c968_u128,
"certificate-autoenrollment"=>0xa266b85ac1e710a7480217bca05b8cc2_u128,
"change-domain-master"=>0xab4fe72b0008f68511d17b3b014bf69c_u128,
"change-infrastructure-master"=>0xcdd5d84fc000d49711d233d9cc17b1fb_u128,
"change-pdc"=>0xcfd4c24fc000529011d14752bae50096_u128,
"change-rid-master"=>0xcdd5d84fc000bbad11d10a98d58d5f36_u128,
"change-schema-master"=>0xcdd5d84fc000bbad11d10a95e12b56b6_u128,
"create-inbound-forest-trust"=>0x33a65bc534be8bb547c3ae17e2a36dc9_u128,
"do-garbage-collection"=>0xcdd5d84fc000bbad11d10a98fec364e0_u128,
"domain-administer-server"=>0x9b524000aa00199811d01e2fab721a52_u128,
"ds-check-stale-phantoms"=>0x05f8794fc000adb911d27f4669ae6200_u128,
"ds-execute-intentions-script"=>0x2e3fa38b38cb2a95432cb98e2f16c4a5_u128,
"ds-install-replica"=>0xb2367af80000beb911d236079923a32a_u128,
"ds-query-self-quota"=>0xbc9d8a2a67eb30b64947ffc04ecc03fe_u128,
"ds-replication-get-changes"=>0xd2dcc24fc0009ff711d19c071131f6aa_u128,
"ds-replication-get-changes-all"=>0xd2dcc24fc0009ff711d19c071131f6ad_u128,
"ds-replication-get-changes-in-filtered-set"=>0x0c64dabeac0f1a994c62444d89e95b76_u128,
"ds-replication-manage-topology"=>0xd2dcc24fc0009ff711d19c071131f6ac_u128,
"ds-replication-monitor-topology"=>0x965a11fabd2e0ba04cdb7c5bf98340fb_u128,
"ds-replication-synchronize"=>0xd2dcc24fc0009ff711d19c071131f6ab_u128,
"enable-per-user-reversibly-encrypted-password"=>0xd57f2a4c66869fbd43b44deb05c74c5e_u128,
"generate-rsop-logging"=>0xf722d3e58099309e4242ab09b7b1b3de_u128,
"generate-rsop-planning"=>0xf722d3e58099309e4242ab09b7b1b3dd_u128,
"manage-optional-features"=>0xdd54ad0a181095a948e4a4197c0e2a7c_u128,
"migrate-sid-history"=>0x0981ff4b5757f3874c764f93ba33815a_u128,
"msmq-open-connector"=>0x0e4d76086000869c11d1df3fb4e60130_u128,
"msmq-peek"=>0x0e4d76086000869c11d1df3e06bd3201_u128,
"msmq-peek-computer-journal"=>0x0e4d76086000869c11d1df3c4b6e08c3_u128,
"msmq-peek-dead-letter"=>0x0e4d76086000869c11d1df3c4b6e08c1_u128,
"msmq-receive"=>0x0e4d76086000869c11d1df3e06bd3200_u128,
"msmq-receive-computer-journal"=>0x0e4d76086000869c11d1df3c4b6e08c2_u128,
"msmq-receive-dead-letter"=>0x0e4d76086000869c11d1df3c4b6e08c0_u128,
"msmq-receive-journal"=>0x0e4d76086000869c11d1df3e06bd3203_u128,
"msmq-send"=>0x0e4d76086000869c11d1df3e06bd3202_u128,
"open-address-book"=>0xcdd5d84fc000e2ad11d14298a1990816_u128,
"read-only-replication-secret-synchronization"=>0xd2dcc24fc0009ff711d19c071131f6ae_u128,
"reanimate-tombstones"=>0x0fc4032debdb3fb547bbdb7e45ec5156_u128,
"recalculate-hierarchy"=>0xcdd5d84fc000bbad11d10a990bc1554e_u128,
"recalculate-security-inheritance"=>0x05f8794fc000adb911d27f4662dd28a8_u128,
"receive-as"=>0x9b524000aa00199811d01e2fab721a56_u128,
"refresh-group-cache"=>0x77f40b6def14588b4db7033c9432c620_u128,
"reload-ssl-certificate"=>0xf89f8aeb71fbdcbc4b2058a61a60ea8d_u128,
"run-protect_admin_groups-task"=>0x7f0ae852e9dcb2a64288a4b47726b9d5_u128,
"sam-enumerate-entire-domain"=>0xecfb7c858ec0798d4acc013591d67418_u128,
"send-as"=>0x9b524000aa00199811d01e2fab721a54_u128,
"send-to"=>0x9b524000aa00199811d01e2fab721a55_u128,
"unexpire-password"=>0x0135c53c4ec046884a7aa6adccc2dc7d_u128,
"update-password-not-required-bit"=>0x41f5c6f3461d98ae438e67c7280f369c_u128,
"update-schema-cache"=>0x05f8794fc000adb911d27f46be2bb760_u128,
"user-change-password"=>0x9b524000aa00199811d01e2fab721a53_u128,
"user-force-change-password"=>0x29056e00aa0068a711d0246d00299570_u128,
"ds-clone-domain-controller"=>0x3e9ab96d924d82ba4c102c7a3e0f7e18_u128,
"ds-read-partition-secrets"=>0x890ede47aef036a84879620d084c93a2_u128,
"ds-write-partition-secrets"=>0x0144f5d8341e46814116b17194825a8d_u128,
"ds-set-owner"=>0x865232419af0b7bc4ff07fac4125c71f_u128,
"ds-bypass-quota"=>0x92806b412725d79d4f2ae5c888a9933e_u128,
"ds-validated-write-computer"=>0xba5c16d79951ee8b465c0d3c9b026da6_u128,

};

// This is still in GUID -> NAME order to match the way the original function is called
pub static PROPERTY_SET_GUID_MAP: phf::Map<&str, u128> = phf::phf_map! {
"general-information"=>0xcfd3c24fc000209011d079a259ba2f42_u128,
"account-restrictions"=>0x29056e00aa0068a711d020c04c164200_u128,
"logon-information"=>0xcfd4c24fc000209011d079a55f202010_u128,
"group-membership"=>0xcfd4c24fc000209011d079a9bc0ac240_u128,
"phone and mail options"=>0xc16703f80000bdae11d19455e45795b2_u128,
"personal-information"=>0xc16703f80000bdae11d1944a77b5b886_u128,
"web-information"=>0xc16703f80000bdae11d19455e45795b3_u128,
"public-information"=>0x5060b94fc000028711d1bcf8e48d0154_u128,
"remote-access-information"=>0x39f968c9a00022b411d20ae1037088f8_u128,
"other-domain-parameters"=>0x9a3f6bc786497aab476204f6b8119fd0_u128,
"dns-host-name-attributes"=>0xcdd5d84fc000efad11d17b1872e39547_u128,
"ms-ts-gatewayaccess"=>0x432572eedf040db44febca4bffa6f046_u128,
"private-information"=>0xd8ccf3f43fd657954b70d96f91e647de_u128,
"terminal-server-license-server"=>0x5e184c0f6a85e2a54428bdc95805bc62_u128,

};
