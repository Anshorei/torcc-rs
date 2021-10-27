use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
	#[error("Unknown key type")]
	UnknownKeyType,
	#[error("Unknown authorization method")]
	UnknownAuthMethod,
	#[error("Auth method disabled")]
	AuthMethodDisabled,
	#[error("I/O Error: `{0}`")]
	Io(#[from] std::io::Error),
	#[error("Internal error parsing controller response")]
	InternalError,
}
