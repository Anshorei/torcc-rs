use std::collections::HashMap;
use std::str::FromStr;

use crate::controller::{AuthMethod, KeyType, ProtocolInfo, ServiceID};
use nom::{
	bytes::complete::{is_not, tag},
	character::complete::line_ending,
	combinator::opt,
	multi::many0,
	multi::separated_list0,
	sequence::{delimited, terminated},
	IResult,
};

pub fn is_final_line(line: &str) -> bool {
	if line.len() < 5 {
		return false;
	}
	for (i, char) in line.chars().enumerate().take(4) {
		match i {
			0 | 1 | 2 => {
				if !char.is_numeric() {
					return false;
				}
			}
			_ => return char.is_whitespace(),
		}
	}
	return false;
}

fn comma_separated_values(input: &str) -> IResult<&str, Vec<&str>> {
	let (remainder, interesting_part) = is_not(" \r\n")(input)?;
	let (_, values) = separated_list0(tag(","), is_not(","))(interesting_part)?;
	return Ok((remainder, values));
}

pub fn is_ok(input: &str) -> IResult<&str, ()> {
	let (i, _) = tag("250 OK")(input)?;
	return Ok((i, ()));
}

pub fn protocol_info(input: &str) -> IResult<&str, ProtocolInfo> {
	let (i, _) = tag("250-PROTOCOLINFO 1")(input)?;
	let (i, _) = line_ending(i)?;

	let (i, methods) = delimited(tag("250-AUTH METHODS="), comma_separated_values, tag(" "))(i)?;
	// TODO: do something with cookiefile
	let (i, _cookiefile) = delimited(tag("COOKIEFILE=\""), is_not("\""), tag("\""))(i)?;
	let (i, _) = line_ending(i)?;

	let (i, version) = delimited(tag("250-VERSION Tor=\""), is_not("\""), tag("\""))(i)?;
	// TODO: use opt version arguments
	let (i, _opt_version_arguments) = opt(is_not("\r\n"))(i)?;
	let (i, _) = line_ending(i)?;

	// TODO: handle optional other line with optional arguments
	let (i, _) = tag("250 OK")(i)?;

	let protocol_info = ProtocolInfo {
		auth_methods: methods
			.iter()
			.map(|method| AuthMethod::from_str(method).unwrap())
			.collect(),
		version:      version.to_string(),
	};
	return Ok((i, protocol_info));
}

pub fn authenticate(input: &str) -> IResult<&str, ()> {
	let (i, _) = tag("250 OK")(input)?;
	return Ok((i, ()));
}

// GETINFO version dormant
// 250-version
// 250-dormant
// 250 OK
pub fn get_info(input: &str) -> IResult<&str, HashMap<String, String>> {
	let (i, pairs) = many0(|i| {
		let (i, key) = delimited(tag("250-"), is_not("="), tag("="))(i)?;
		let (i, value) = terminated(is_not("\r\n"), line_ending)(i)?;
		Ok((i, (key, value)))
	})(input)?;

	let mut response = HashMap::new();
	for (key, value) in pairs.into_iter() {
		response.insert(key.to_string(), value.to_string());
	}

	Ok((i, response))
}

// named!(pub get_info_version <&str, Vec<(&str, &str)> >,
//   do_parse!(
//     tag_s!("250-") >>
//     opts: keys_and_values >>
//     take_till_s!(is_next_line) >>
//     tag_s!("\n250 OK") >>
//     (opts)
//   )
// );

pub fn add_onion(input: &str) -> IResult<&str, (ServiceID, Option<(KeyType, String)>)> {
	let (i, _) = tag("250-ServiceID=")(input)?;
	let (i, service_id) = is_not("\r\n")(i)?;
	let (i, _) = line_ending(i)?;

	let (i, key) = opt(|i| {
		let (i, key_type) = delimited(tag("250-PrivateKey="), is_not(":"), tag(":"))(i)?;
		let (i, key_blob) = is_not("\r\n")(i)?;
		let (i, _) = line_ending(i)?;

		let key_type = KeyType::from_str(key_type).unwrap();
		Ok((i, (key_type, key_blob.to_string())))
	})(i)?;

	// TODO: do something with optional client parameters
	let (i, _client) = opt(|i| {
		let (i, client_name) = delimited(tag("250-ClientAuth="), is_not(":"), tag(":"))(i)?;
		let (i, client_blob) = is_not("\r\n")(i)?;
		let (i, _) = line_ending(i)?;
		Ok((i, (client_name, client_blob)))
	})(i)?;

	let (i, _) = tag("250 OK")(i)?;

	let service_id = ServiceID::from(service_id.to_string());
	return Ok((i, (service_id, key)));
}

#[cfg(test)]
mod tests {
	use crate::controller::{AuthMethod, KeyType, ProtocolInfo, ServiceID};
	use nom::IResult;

	#[test]
	fn test_protocol_info() {
		use crate::parsers::protocol_info;

		assert_eq!(
      protocol_info("250-PROTOCOLINFO 1\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/var/run/tor/control.authcookie\"\n250-VERSION Tor=\"0.1.2.3\"\n250 OK"),
      Ok(("", ProtocolInfo {
        auth_methods: vec![AuthMethod::Cookie, AuthMethod::SafeCookie],
        version: "0.1.2.3".to_string(),
      }))
    )
	}

	#[test]
	fn test_authenticate() {
		use crate::parsers::authenticate;

		assert_eq!(authenticate("250 OK"), Ok(("", ())),)
	}

	#[test]
	fn test_get_info_version() {
		use crate::parsers::get_info;

		let (_, info) = get_info("250-version=0.1.2.3\n250 OK").expect("Error parsing response");
		assert_eq!(info.get("version"), Some(&String::from("0.1.2.3")),)
	}

	// //   ADD_ONION NEW:RSA1024 port=12345
	// // 250-ServiceID=k2edzso5c4rxyay3
	// // 250-PrivateKey=RSA1024:MIICWwIBAAKBgQDKw9sSdcO05FDrroFKPKpbk+fWS4zSD8f7CKWpMfy2TA5yjE4mtYNT7Dd9JeiGUl/ezs0Ffjd8gT840TExJiZOGumHmPo2O/6V3n0J5iLvvn0fKzrIopXUvbzhfVXr9WYHdSgd0wMxVUOmMyEI2jQwUpQqFYTsSIyngFuffd5SXQIDAQABAoGASe9avYN1hktOenHaMRCn6danzcskoSAiApZnmadhh7N5/SjOAm1jYsGahibBf+EfliYAOkWIw/x46iXVcx9/DYtQRHCghkEewpSq93oIVEnFV/4kB3wmobhX93b8dObHqXWyNrxcmE/x5Li+7pHJZBxSsqbSCJyUffFMqVnpVSECQQD0arFjflEMnXph4DOnSwE2HOBqFxdRnkwvNYXtlpbew83T7Q49wjMax80KfspwSryN+H0Lnt4jrAj8ATj1tJ7VAkEA1F/WRjprvVqTa8F7uUJIj4kzvJYY0eRvJYmZQZE/b4Vqj7KWgKkfmm9JMgWRaxR8aonL+2Asu5er1cYAhRz5aQJAaFHxjImphjzgs03CPjEhPztr/VwFs+xgj/XER/fyRPpFq6KOZYWx0khdF5GuTedYOzBIDuGr5oXS/9x1t0l0UQJAPsdZwwbQBHh67baTSU9TvcJ0HcJM8fbR+Em1mRFDrEbHGlVTchMMeY1+GKBWvU2f/apgNx3V+1o5fIb8bl0DSQJAYue7LG0l0DABNaU1DKPqHuUQA61WZLEGjucAIhD3TSxnRhSEbDqqf+siUthwezd6k5Q3rVrRtfiGOA5t6bq/cw==

	#[test]
	fn add_onion() {
		use crate::parsers::add_onion;

		assert_eq!(
			add_onion("250-ServiceID=rdwu5tfgmibbgvff\n250-PrivateKey=RSA1024:MIIC\n250 OK"),
			Ok((
				"",
				(
					ServiceID::from("rdwu5tfgmibbgvff".to_string()),
					Some((KeyType::RSA1024, "MIIC".to_string())),
				),
			))
		)
	}

	//   DEL_ONION k2edzso5c4rxyay3
	// 250 OK
}
