use nom::{
    IResult,
    bytes::complete::tag,
    combinator::{map, opt},
    branch::alt,
    sequence::tuple
};
use std::io::{Read, BufRead, Write};

enum Mechanism {
    External,
}

enum ClientCommand<'i> {
    Auth {
        mechanism: Option<Mechanism>,
        initial_response: Option<&'i str>,
    },
    Cancel,
    Begin,
    Data(&'i str),
    Error(Option<&'i str>),
    NegotiateUnixFd,
}

enum ServerCommand {
    Rejected(Mechanism),
    Ok(String),
    Data(String),
    Error(Option<String>),
    AgreeUnixFd,
}

struct Parser<'i> {
    _p: std::marker::PhantomData<&'i ()>,
}

impl<'i> Parser<'i> {
    pub fn new() -> Self {
	Self {
	    _p: std::marker::PhantomData
	}
    }
    fn parse_client_command(input: &'i str) -> IResult<&'i str, ClientCommand<'i>> {
	alt((
	    Self::parse_auth,
	    Self::parse_cancel,
	    Self::parse_begin,
	    Self::parse_client_data,
	    Self::parse_client_error,
	    Self::parse_negotiate_unix_fd
	))(input)
    }
    
    fn parse_mechanism(input: &'i str) -> IResult<&'i str, Mechanism> {
        map(tag("EXTERNAL"), |_| Mechanism::External)(input)
    }

    fn parse_auth(input: &'i str) -> IResult<&'i str, ClientCommand<'i>> {
	use nom::sequence::preceded;
	use nom::character::complete::char;
	use nom::bytes::complete::take_until;
	
	let (input, (_, mechanism, initial_response)) = tuple((
	    tag("AUTH"),
	    opt(preceded(char(' '), Self::parse_mechanism)),
	    opt(preceded(char(' '), take_until("\r\n")))
	))(input)?;

	let auth = ClientCommand::Auth {
	    mechanism,
	    initial_response
	};

	Ok((input, auth))
    }

    fn parse_cancel(input: &'i str) -> IResult<&'i str, ClientCommand<'i>> {
	map(tag("CANCEL"), |_| ClientCommand::Cancel)(input)
    }

    fn parse_begin(input: &'i str) -> IResult<&'i str, ClientCommand<'i>> {
	map(tag("BEGIN"), |_| ClientCommand::Begin)(input)
    }

    fn parse_client_data(input: &'i str) -> IResult<&'i str, ClientCommand<'i>> {
	use nom::sequence::preceded;
	use nom::character::complete::char;
	use nom::bytes::complete::take_until;

	let (input, data) = preceded(
	    tag("DATA"),
	    preceded(char(' '), take_until("\r\n"))
	)(input)?;

	let data = ClientCommand::Data(data);
	Ok((input, data))
    }

    fn parse_client_error(input: &'i str) -> IResult<&'i str, ClientCommand<'i>> {
	use nom::sequence::preceded;
	use nom::character::complete::char;
	use nom::bytes::complete::take_until;

	let (input, description) = preceded(
	    tag("ERROR"),
	    opt(preceded(char(' '), take_until("\r\n")))
	)(input)?;

	let error = ClientCommand::Error(description);
	Ok((input, error))
    }

    fn parse_negotiate_unix_fd(input: &'i str) -> IResult<&'i str, ClientCommand<'i>> {
	map(tag("NEGOTIATE_UNIX_FD"), |_| ClientCommand::NegotiateUnixFd)(input)
    }
}

struct Encoder<W> {
    writer: W
}

impl<W: std::io::Write> Encoder<W> {
    pub fn new(writer: W) -> Self {
	Self {
	    writer
	}
    }

    pub fn write_mechanism(&mut self, m: Mechanism) -> std::io::Result<()> {
	match m {
	    Mechanism::External => self.writer.write(b"EXTERNAL")?
	};
	Ok(())
    }

    #[inline]
    pub fn write_endln(&mut self) -> std::io::Result<()> {
	self.writer.write(b"\r\n")?;
	Ok(())
    }

    pub fn write_command(&mut self, cmd: ServerCommand) -> std::io::Result<()> {
	match cmd {
	    ServerCommand::Rejected(m) => {
		self.writer.write(b"REJECTED ")?;
		self.write_mechanism(m)?;
	    },
	    ServerCommand::Ok(data) => {
		self.writer.write(b"OK ")?;
		self.writer.write(data.as_bytes())?;
	    },
	    ServerCommand::Data(data) => {
		self.writer.write(b"DATA ")?;
		self.writer.write(data.as_bytes())?;
	    }
	    ServerCommand::Error(err) => {
		self.writer.write(b"ERROR")?;
		if let Some(err) = err {
		    self.writer.write(b" ")?;
		    self.writer.write(err.as_bytes())?;
		}
	    }
	    ServerCommand::AgreeUnixFd => {
		self.writer.write(b"AGREE_UNIX_FD")?;
	    }
	};
	self.write_endln()?;

	Ok(())
    }
}

enum AuthState {
    WaitingForAuth,
    WaitingForData,
    WaitingForBegin
}

struct AuthenticationFlow<R, W> {
    r: R,
    w: Encoder<W>,
    state: AuthState,
    buf: String,
}

impl<R: BufRead, W: Write> AuthenticationFlow<R, W> {
    pub fn new(r: R, w: W) -> Self {
	Self {
	    r,
	    w: Encoder::new(w),
	    state: AuthState::WaitingForAuth,
	    buf: String::new(),
	}
    }

    pub fn get_client_command(&mut self) -> std::io::Result<ClientCommand> {
	self.buf.clear();
	self.r.read_line(&mut self.buf)?;
	if let Ok((_, c)) = Parser::parse_client_command(&self.buf) {
	    Ok(c)
	} else {
	    Err(std::io::Error::from(std::io::ErrorKind::InvalidInput))
	}
    }

    pub fn write_server_command(&mut self, cmd: ServerCommand) -> std::io::Result<()> {
	self.w.write_command(cmd)
    }

    pub fn flow(&mut self) -> std::io::Result<Option<()>> {
	loop {
	    match self.state {
		AuthState::WaitingForAuth => {
		    let cmd = self.get_client_command()?;
		    match cmd {
			ClientCommand::Auth { mechanism: None, .. } | ClientCommand::Error(_) => {
			    self.write_server_command(ServerCommand::Rejected(Mechanism::External))?
			},
			ClientCommand::Auth { .. } => {
			    self.write_server_command(ServerCommand::Ok("<SERVER GUID HERE>".to_string()))?; // TODO
			    self.state = AuthState::WaitingForBegin;
			},
			ClientCommand::Begin => {
			    return Ok(None);
			},
			_ => {
			    self.write_server_command(ServerCommand::Error(None))?;
			}
		    }
		},
		AuthState::WaitingForData => {
		    let cmd = self.get_client_command()?;
		    match cmd {
			ClientCommand::Data(_) => {
			    self.write_server_command(ServerCommand::Ok("<SERVER GUID HERE>".to_string()))?; // TODO
			    self.state = AuthState::WaitingForBegin;
			},
			ClientCommand::Begin => {
			    return Ok(None);
			},
			ClientCommand::Cancel | ClientCommand::Error(_) => {
			    self.write_server_command(ServerCommand::Rejected(Mechanism::External))?;
			    self.state = AuthState::WaitingForAuth;
			},
			_ => {
			    self.write_server_command(ServerCommand::Error(None))?;
			}
		    }
		},
		AuthState::WaitingForBegin => {
		    let cmd = self.get_client_command()?;
		    match cmd {
			ClientCommand::Begin => {
			    return Ok(Some(()));
			},
			ClientCommand::NegotiateUnixFd => {
			    self.write_server_command(ServerCommand::AgreeUnixFd)?;
			},
			ClientCommand::Cancel | ClientCommand::Error(_) => {
			    self.write_server_command(ServerCommand::Rejected(Mechanism::External))?;
			    self.state = AuthState::WaitingForAuth;
			},
			_ => {
			    self.write_server_command(ServerCommand::Error(None))?;
			}
		    }
		}
	    }
	}
    }
}
