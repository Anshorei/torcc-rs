use std::collections::HashMap;
use std::io::prelude::*;

use std::fmt::{Debug, Write as FmtWrite};
use std::io::{BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::str::FromStr;

use nom::IResult;

use crate::parsers;

mod error;
use error::Error;

const DEFAULT_API: &'static str = "127.0.0.1:9051";

#[derive(Debug, PartialEq, Eq)]
pub struct ProtocolInfo {
	pub auth_methods: Vec<AuthMethod>,
	pub version:      String,
	pub cookiefile: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthMethod {
	Cookie,
	SafeCookie,
	HashedPassword,
}

impl FromStr for AuthMethod {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"COOKIE" => Ok(AuthMethod::Cookie),
			"SAFECOOKIE" => Ok(AuthMethod::SafeCookie),
			"HASHEDPASSWORD" => Ok(AuthMethod::HashedPassword),
			_ => Err(Error::UnknownAuthMethod),
		}
	}
}

pub enum Signal {
	Reload,
	Shutdown,
	Dump,
	Debug,
	Halt,
	ClearDNSCache,
	Newnym,
	Heartbeat,
	Dormant,
	Active,
}

impl ToString for Signal {
	fn to_string(&self) -> String {
		match self {
			Signal::Reload => "RELOAD".to_string(),
			Signal::Shutdown => "SHUTDOWN".to_string(),
			Signal::Dump => "DUMP".to_string(),
			Signal::Debug => "DEBUG".to_string(),
			Signal::Halt => "HALT".to_string(),
			Signal::ClearDNSCache => "CLEARDNSCACHE".to_string(),
			Signal::Newnym => "NEWNYM".to_string(),
			Signal::Heartbeat => "HEARTBEAT".to_string(),
			Signal::Dormant => "DORMANT".to_string(),
			Signal::Active => "ACTIVE".to_string(),
		}
	}
}

pub enum AddOnionFlag {
	DiscardPK,
	Detach,
	BasicAuth,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyType {
	Best,
	RSA1024,
	ED25519V3,
}

impl Default for KeyType {
	fn default() -> Self {
		KeyType::Best
	}
}

impl ToString for KeyType {
	fn to_string(&self) -> String {
		match &self {
			KeyType::ED25519V3 => String::from("ED25519-V3"),
			KeyType::RSA1024 => String::from("RSA1024"),
			KeyType::Best => String::from("BEST"),
		}
	}
}

impl FromStr for KeyType {
	type Err = Error;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		return match s {
			"ED25519-V3" => Ok(KeyType::ED25519V3),
			"RSA1024" => Ok(KeyType::RSA1024),
			_ => Err(Error::UnknownKeyType),
		};
	}
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServiceID(String);

impl From<&str> for ServiceID {
	fn from(service_id: &str) -> Self {
		ServiceID(service_id.to_string())
	}
}

impl From<String> for ServiceID {
	fn from(service_id: String) -> Self {
		ServiceID(service_id)
	}
}

pub struct HiddenService {
	pub service_id:  ServiceID,
	pub key_type:    KeyType,
	pub private_key: String,
}

pub struct TorController {
	conn: TcpStream,
}

impl TorController {
	fn send<F, T>(&mut self, msg: String, reply_parser: F) -> Result<T, Error>
	where
		T: Debug,
		F: Fn(&str) -> IResult<&str, T>,
	{
		debug!("-> {}", &msg);
		let bytes = format!("{}\r\n", msg).into_bytes();
		self.conn.write_all(&bytes)?;

		let mut reader = BufReader::new(&self.conn);
		let mut buffer = String::new();
		loop {
			let mut line = String::new();
			reader.read_line(&mut line)?;
			buffer.push_str(&line);
			if parsers::is_final_line(&line) {
				break;
			}
		}

		debug!("<- {}", &buffer);
		let comparison = "250-PROTOCOLINFO 1\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/run/tor/control.authcookie\"\n250-VERSION Tor=\"0.1.2.3\"\n250 OK".to_string();
		debug!("<- {}", &comparison);

		return match reply_parser(&buffer) {
			Ok((_, response)) => Ok(response),
			Err(_) => Err(Error::InternalError),
		};
	}

	fn authenticate(&mut self, password: String) -> Result<(), Error> {
		let authentication_string = format!("AUTHENTICATE \"{}\"", password.replace("\"", "\\\""));
		self.send(authentication_string, parsers::is_ok)?;

		Ok(())
	}

	// pub fn authenticate_authcookie(&mut self, password: String) -> Result<(), Error> {
	// 	let protocol_info = self.protocol_info()?;
	// 	unimplemented!();
	// 	Ok(())
	// }

	pub fn protocol_info(&mut self) -> Result<ProtocolInfo, Error> {
		let response = self.send(String::from("PROTOCOLINFO"), parsers::protocol_info)?;

		Ok(response)
	}

	fn connect<A: ToSocketAddrs>(addr: A) -> Result<TorController, Error> {
		let conn = TcpStream::connect(addr)?;
		let controller = Self { conn };
		Ok(controller)
	}

	pub fn connect_default_with_authcookie() -> Result<TorController, Error> {
		TorController::connect_with_authcookie(DEFAULT_API)
	}

	pub fn connect_with_authcookie<A: ToSocketAddrs>(addr: A) -> Result<TorController, Error> {
		let mut controller = TorController::connect(addr)?;
		let protocol_info = controller.protocol_info()?;

		let contents = std::fs::read(&protocol_info.cookiefile).unwrap();
		let mut cookie_string = String::new();
		contents.into_iter().for_each(|b| write!(cookie_string, "{:02X}", b).unwrap());

		let msg = format!("AUTHENTICATE {}", cookie_string);
		controller.send(msg, parsers::is_ok)?;

		Ok(controller)
	}

	pub fn connect_default_with_password(password: String) -> Result<TorController, Error> {
		TorController::connect_with_password(DEFAULT_API, password)
	}

	pub fn connect_with_password<A: ToSocketAddrs>(
		addr: A,
		password: String,
	) -> Result<TorController, Error> {
		let mut controller = TorController::connect(addr)?;

		let protocol_info = controller.protocol_info()?;

		if !protocol_info
			.auth_methods
			.contains(&AuthMethod::HashedPassword)
		{
			return Err(Error::AuthMethodDisabled);
		}

		controller.authenticate(password)?;

		Ok(controller)
	}

	pub fn add_onion(&mut self, key_type: KeyType, port: u16) -> Result<HiddenService, Error> {
		let add_onion_command = format!("ADD_ONION NEW:{} port={}", key_type.to_string(), port);
		let (service_id, key) = self.send(add_onion_command, parsers::add_onion)?;
		let (key_type, private_key) = key.unwrap();
		let hidden_service = HiddenService {
			service_id,
			key_type,
			private_key,
		};

		Ok(hidden_service)
	}

	pub fn add_onion_default(&mut self, port: u16) -> Result<HiddenService, Error> {
		self.add_onion(KeyType::default(), port)
	}

	pub fn add_onion_with_key(
		&mut self,
		key_type: KeyType,
		key: String,
		port: u16,
	) -> Result<HiddenService, Error> {
		let add_onion_command = format!("ADD_ONION {}:{} port={}", key_type.to_string(), key, port);
		let (service_id, optional_key) = self.send(add_onion_command, parsers::add_onion)?;
		let (key_type, private_key) = optional_key.unwrap();
		let hidden_service = HiddenService {
			service_id,
			private_key,
			key_type,
		};

		Ok(hidden_service)
	}

	// Delete an onion with the given service id
	pub fn delete_onion(&mut self, service_id: ServiceID) -> Result<(), Error> {
		let del_onion_command = format!("DEL_ONION {}", service_id.0);
		self.send(del_onion_command, parsers::is_ok)?;

		Ok(())
	}

	pub fn get_info(&mut self, info_fields: Vec<&str>) -> Result<HashMap<String, String>, Error> {
		let get_info_command = format!("GETINFO {}", info_fields.join(" "));
		let response = self.send(get_info_command, parsers::get_info)?;

		Ok(response)
	}

	pub fn signal(&mut self, signal: Signal) -> Result<(), Error> {
		let signal_command = format!("SIGNAL {}", signal.to_string());
		self.send(signal_command, parsers::is_ok)?;

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn init() {
		let _ = env_logger::builder().is_test(true).try_init();
	}

	fn get_controller() -> TorController {
		TorController::connect_default_with_authcookie().unwrap()
	}

	#[test]
	fn establish_connection() {
		init();

		let password =
			std::env::var("TOR_CONTROLLER_PASSWORD").expect("TOR_CONTROLLER_PASSWORD is not set");
		let result = TorController::connect_default_with_password(password);
		assert!(result.is_ok());
	}

	#[test]
	fn create_onion() {
		init();

		let mut controller = get_controller();
		let hidden_service = controller.add_onion(KeyType::Best, 80);
		assert!(hidden_service.is_ok());
	}

	#[test]
	fn delete_onion() {
		init();

		let mut controller = get_controller();
		let hidden_service = controller
			.add_onion_default(80)
			.expect("Error adding onion");
		assert!(controller.delete_onion(hidden_service.service_id).is_ok());
	}

	#[test]
	fn delete_fake_onion() {
		let mut controller = get_controller();
		let service_id = ServiceID::from("does not exist".to_string());
		assert!(controller.delete_onion(service_id).is_err());
	}

	#[test]
	fn get_info() {
		let mut controller = get_controller();
		let info = controller.get_info(vec!["version"]).unwrap();
		assert!(info.contains_key("version"));
	}
}
