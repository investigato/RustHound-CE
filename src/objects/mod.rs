//! All structure needed by RustHound-CE.
//!
//! Example in rust:
//!
//! ```rust
//! # use rusthound_ce::objects::user::User;
//! # use rusthound_ce::objects::group::Group;
//! # use rusthound_ce::objects::computer::Computer;
//! # use rusthound_ce::objects::ou::Ou;
//! # use rusthound_ce::objects::gpo::Gpo;
//! # use rusthound_ce::objects::domain::Domain;
//! # use rusthound_ce::objects::container::Container;
//!
//! let user = User::new();
//! let group = Group::new();
//! let computer = Computer::new();
//! let ou = Ou::new();
//! let gpo = Gpo::new();
//! let domain = Domain::new();
//! let container = Container::new();
//! ```
//!
pub mod aiaca;
pub mod attribute;
pub mod certtemplate;
pub mod common;
pub mod computer;
pub mod container;
pub mod delegatedmsa;
pub mod domain;
pub mod enterpriseca;
pub mod fsp;
pub mod gpo;
pub mod group;
pub mod issuancepolicy;
pub mod ntauthstore;
pub mod ou;
pub mod rootca;
pub mod trust;
pub mod user;
