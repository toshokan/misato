use nom::IResult;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::map,
    number::Endianness,
};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    #[inline]
    fn is_little(&self) -> bool {
        match self {
            Self::Little => true,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MessageType {
    Invalid,
    MethodCall,
    MethodReturn,
    Error,
    Signal,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MajorProtoVersion {
    V1,
}

#[derive(PartialEq, Eq)]
pub struct HeaderFlags(u8);

#[derive(Debug, PartialEq, Eq)]
pub struct Serial(u32);

impl Serial {
    pub fn as_u32(&self) -> u32 {
	self.0
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct HeaderFields<'i> {
    pub path: Option<&'i str>,
    pub interface: Option<&'i str>,
    pub member: Option<&'i str>,
    pub error_name: Option<&'i str>,
    pub reply_serial: Option<u32>,
    pub destination: Option<&'i str>,
    pub sender: Option<&'i str>,
    pub signature: Option<Vec<Type>>,
    pub unix_fds: Option<u32>
}

#[derive(Debug, PartialEq)]
pub struct MessageHeader<'i> {
    pub endianness: Endian,
    pub kind: MessageType,
    pub flags: HeaderFlags,
    pub proto_version: MajorProtoVersion,
    pub len: u32,
    pub serial: Serial,
    pub fields: HeaderFields<'i>,
}

pub struct Message<'i> {
    pub header: MessageHeader<'i>,
    pub body: Vec<Data<'i>>
}

impl<'i> Message<'i> {
    pub fn into_parts(self) -> (MessageHeader<'i>, Vec<Data<'i>>) {
	(self.header, self.body)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Type {
    Invalid,
    Byte,
    Boolean,
    Int16,
    UInt16,
    Int32,
    UInt32,
    Int64,
    UInt64,
    Double,
    String,
    ObjectPath,
    Signature,
    Array(Box<Type>),
    Struct(Vec<Type>),
    Variant,
    DictEntry(Box<Type>, Box<Type>),
    UnixFd,
}

#[derive(Debug)]
pub enum Data<'i> {
    Invalid,
    Byte(u8),
    Boolean(bool),
    Int16(i16),
    UInt16(u16),
    Int32(i32),
    UInt32(u32),
    Int64(i64),
    UInt64(u64),
    Double(f64),
    String(&'i str),
    ObjectPath(&'i str),
    Signature(Vec<Type>),
    Array(Vec<Data<'i>>),
    Struct(Vec<Data<'i>>),
    Variant(Type, Box<Data<'i>>),
    DictEntry(Box<Data<'i>>, Box<Data<'i>>),
    UnixFd(u32),
}

impl HeaderFlags {
    pub fn as_u8(&self) -> u8 {
	self.0
    }
    
    #[inline]
    fn check_flag(&self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    #[inline]
    pub fn no_reply_expected(&self) -> bool {
        self.check_flag(1)
    }

    #[inline]
    pub fn no_auto_start(&self) -> bool {
        self.check_flag(2)
    }

    #[inline]
    pub fn allow_interactive_authorization(&self) -> bool {
        self.check_flag(4)
    }
}

impl std::fmt::Debug for HeaderFlags {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
	fmt.debug_struct("HeaderFlags")
	    .field("no_reply_expected", &self.no_reply_expected())
	    .field("no_auto_start", &self.no_auto_start())
	    .field("allow_interactive_authorization", &self.allow_interactive_authorization())
	    .finish()
    }
}

pub struct Parser<'i> {
    src: &'i [u8],
    endian: Endianness,
}

macro_rules! num_parser {
	($(($parser_name:ident, $alignment:expr, $parse_fn:expr, $ret:ty)),*) => {
	    $(
		pub fn $parser_name(&self, input: &'i [u8]) -> IResult<&'i [u8], $ret> {
		    use nom::number::complete::*;

		    let (input, _) = self.align_at(input, $alignment)?;
		    $parse_fn(self.endian)(input)
		}
	    )*
	}
}

impl<'i> Parser<'i> {
    pub fn new(input: &'i [u8]) -> Self {
        Self {
            src: input,
            endian: Endianness::Little,
        }
    }

    pub fn parse_header(&mut self, input: &'i [u8]) -> IResult<&'i [u8], MessageHeader> {
	use nom::sequence::tuple;

	let (input, endianness) = self.parse_endianness(input)?;

	let (input, (kind, flags, proto_version, len, serial, fields)) = tuple((
	    |i| self.parse_message_type(i),
	    |i| self.parse_header_flags(i),
	    |i| self.parse_major_proto_version(i),
	    |i| self.parse_uint32(i),
	    |i| self.parse_serial(i),
	    |i| self.parse_header_fields(i)
	))(input)?;

	let hdr = MessageHeader {
	    endianness,
	    kind,
	    flags,
	    proto_version,
	    len,
	    serial,
	    fields
	};
	
	Ok((input, hdr))
    }

    pub fn parse_header_fields(&self, input: &'i [u8]) -> IResult<&'i [u8], HeaderFields<'i>>{
	let (mut input, count) = self.parse_uint32(input)?;
	let mut fields = HeaderFields::default();

	for _ in 0..count {
	    let (r, tag) = self.parse_byte(input)?;
	    let (r, data) = self.parse_variant(r)?;
	    input = r;

	    if let Data::Variant(_, data) = data {
		match (tag, *data) {
		    (1, Data::ObjectPath(s)) => fields.path = Some(s),
		    (2, Data::String(s)) => fields.interface = Some(s),
		    (3, Data::String(s)) => fields.member = Some(s),
		    (4, Data::String(s)) => fields.error_name = Some(s),
		    (5, Data::UInt32(n)) => fields.reply_serial = Some(n),
		    (6, Data::String(s)) => fields.destination = Some(s),
		    (7, Data::String(s)) => fields.sender = Some(s),
		    (8, Data::Signature(tys)) => fields.signature = Some(tys),
		    (9, Data::UInt32(n)) => fields.unix_fds = Some(n),
		    _ => continue,
		}
	    }
	}

	Ok((input, fields))
    }

    pub fn parse_data(&self, ty: Type, input: &'i [u8]) -> IResult<&'i [u8], Data<'i>> {
        macro_rules! data_parser {
            ($tag:expr, $parse_method:path) => {
                map(|i| $parse_method(self, i), |x| $tag(x))
            };
        }
        match ty {
            Type::Byte => data_parser!(Data::Byte, Self::parse_byte)(input),
            Type::Boolean => data_parser!(Data::Boolean, Self::parse_boolean)(input),
            Type::Int16 => data_parser!(Data::Int16, Self::parse_int16)(input),
            Type::UInt16 => data_parser!(Data::UInt16, Self::parse_uint16)(input),
            Type::Int32 => data_parser!(Data::Int32, Self::parse_int32)(input),
            Type::UInt32 => data_parser!(Data::UInt32, Self::parse_uint32)(input),
            Type::Int64 => data_parser!(Data::Int64, Self::parse_int64)(input),
            Type::UInt64 => data_parser!(Data::UInt64, Self::parse_uint64)(input),
            Type::Double => data_parser!(Data::Double, Self::parse_double)(input),
            Type::String => data_parser!(Data::String, Self::parse_string)(input),
            Type::ObjectPath => data_parser!(Data::ObjectPath, Self::parse_object_path)(input),
            Type::Signature => data_parser!(Data::Signature, Self::parse_signature)(input),
            Type::Array(ty) => self.parse_array(*ty, input),
            Type::Struct(tys) => self.parse_struct(tys, input),
            Type::Variant => self.parse_variant(input),
            Type::DictEntry(k, v) => self.parse_struct(vec![*k,*v], input),
            Type::UnixFd => data_parser!(Data::UnixFd, Self::parse_uint32)(input),
            _ => unimplemented!(),
        }
    }

    #[inline]
    fn align_at(&self, input: &'i [u8], multiple: usize) -> IResult<&'i [u8], ()> {
        use nom::Offset;

        let offset = self.src.offset(input);
        let rem = offset % multiple;
        if rem == 0 {
            Ok((input, ()))
        } else {
            map(take(multiple - rem), |_| ())(input)
        }
    }

    pub fn parse_byte(&self, input: &'i [u8]) -> IResult<&'i [u8], u8> {
        map(take(1_usize), |b: &[u8]| b[0])(input)
    }

    pub fn parse_boolean(&self, input: &'i [u8]) -> IResult<&'i [u8], bool> {
        let (input, n) = self.parse_uint32(input)?;
        match n {
            1_u32 => Ok((input, true)),
            0_u32 => Ok((input, false)),
            _ => Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            ))),
        }
    }

    num_parser![
        (parse_int16, 2, i16, i16),
        (parse_uint16, 2, u16, u16),
        (parse_int32, 4, i32, i32),
        (parse_uint32, 4, u32, u32),
        (parse_int64, 8, i64, i64),
        (parse_uint64, 8, u64, u64),
        (parse_double, 8, f64, f64)
    ];

    pub fn parse_string(&self, input: &'i [u8]) -> IResult<&'i [u8], &'i str> {
	use nom::sequence::tuple;
	use nom::character::complete::char;

        let (input, len) = self.parse_uint32(input)?;
	let (input, (bytes, _)) = tuple((
	    take(len),
	    char('\0')
	))(input)?;
	let str = unsafe {
	    std::str::from_utf8_unchecked(bytes)
	};
	Ok((input, str))
    }

    pub fn parse_object_path(&self, input: &'i [u8]) -> IResult<&'i [u8], &'i str> {
        self.parse_string(input)
    }

    pub fn parse_ty(&self, input: &'i [u8]) -> IResult<&'i [u8], Type> {
	use nom::sequence::{delimited, tuple};
	use nom::multi::many1;
	
	macro_rules! tagged_type {
	    ($(($tag:expr, $ty:expr)),*) => {
		alt((
		    $(
			map(tag($tag), |_| $ty)
		    ),*
		))
	    }
	}

	alt((
	    map(tuple((tag("a"), |i| self.parse_ty(i))), |(_, ty)| Type::Array(Box::new(ty))),
	    map(delimited(tag("("), many1(|i| self.parse_ty(i)), tag(")")), |tys| Type::Struct(tys)),
	    tagged_type! [
		("y", Type::Byte),
		("b", Type::Boolean),
		("n", Type::Int16),
		("q", Type::UInt16),
		("i", Type::Int32),
		("u", Type::UInt32),
		("x", Type::Int64),
		("t", Type::UInt64),
		("d", Type::Double),
		("s", Type::String),
		("o", Type::ObjectPath),
		("g", Type::Signature),
		("v", Type::Variant)
	    ]
	))(input)
    }

    pub fn parse_signature(&self, input: &'i [u8]) -> IResult<&'i [u8], Vec<Type>> {
	use nom::combinator::all_consuming;
	use nom::multi::many0;
	
        let (input, len) = self.parse_byte(input)?;
	let (input, bytes) = take(len)(input)?;
	let (_, signature) = all_consuming(many0(|i| self.parse_ty(i)))(bytes)?;
	
	Ok((input, signature))
    }

    pub fn parse_array(&self, ty: Type, input: &'i [u8]) -> IResult<&'i [u8], Data<'i>> {
        use nom::multi::many_m_n;

	let parselet = |i| self.parse_data(ty.clone(), i);

        let (input, len) = self.parse_uint32(input)?;
        let len = len as usize;
        map(many_m_n(len, len, parselet), |data| Data::Array(data))(input)
    }

    pub fn parse_struct(&self, tys: Vec<Type>, input: &'i [u8]) -> IResult<&'i [u8], Data<'i>> {
	let (mut input, _) = self.align_at(input, 8)?;
	
	let mut fields = vec![];
	for ty in tys {
	    let (r, field) = self.parse_data(ty, input)?;
	    input = r;
	    fields.push(field)
	}
	
	Ok((input, Data::Struct(fields)))
    }

    pub fn parse_endianness(&mut self, input: &'i [u8]) -> IResult<&'i [u8], Endian> {
        let (input, e) = alt((
            map(tag("B"), |_| Endian::Big),
            map(tag("l"), |_| Endian::Little),
        ))(input)?;

        self.endian = if e.is_little() {
            Endianness::Little
        } else {
            Endianness::Big
        };
        Ok((input, e))
    }

    fn parse_message_type(&self, input: &'i [u8]) -> IResult<&'i [u8], MessageType> {
        alt((
            map(tag("\0"), |_| MessageType::Invalid),
            map(tag("\u{1}"), |_| MessageType::MethodCall),
            map(tag("\u{2}"), |_| MessageType::MethodReturn),
            map(tag("\u{3}"), |_| MessageType::Error),
            map(tag("\u{4}"), |_| MessageType::Signal),
        ))(input)
    }

    fn parse_header_flags(&self, input: &'i [u8]) -> IResult<&'i [u8], HeaderFlags> {
        map(take(1_usize), |flags: &[u8]| HeaderFlags(flags[0]))(input)
    }

    fn parse_major_proto_version(&self, i: &'i [u8]) -> IResult<&'i [u8], MajorProtoVersion> {
	map(tag("\u{1}"), |_| MajorProtoVersion::V1)(i)
    }

    fn parse_serial(&self, input: &'i [u8]) -> IResult<&'i [u8], Serial> {
	map(|i| self.parse_uint32(i), |s| Serial(s))(input)
    }

    fn parse_variant(&self, input: &'i [u8]) -> IResult<&'i [u8], Data<'i>> {
	let (input, ty) = self.parse_ty(input)?;
	let cty = ty.clone();
	map(move |i| self.parse_data(ty.clone(), i), move |d| Data::Variant(cty.clone(), Box::new(d)))(input)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_signatures() {
	use Type::*;
	
	let input = "\u{b}yyyyuua(yv)";
	let parser = Parser::new(&input.as_bytes());
	let (_, x) = parser.parse_signature(&input.as_bytes()).unwrap();
	assert_eq!(x, vec![Byte, Byte, Byte, Byte, UInt32, UInt32, Array(Box::new(Struct(vec![Byte, Variant]))) ]);
    }

    #[test]
    fn parses_compex_arrays() {
	use Type::*;
	
	let input = "\u{3}aay";
	let parser = Parser::new(&input.as_bytes());
	let (_, x) = parser.parse_signature(&input.as_bytes()).unwrap();
	assert_eq!(x, vec![Array(Box::new(Array(Box::new(Byte))))]);
    }

    #[test]
    fn parses_strings() {
	use Type::*;
	
	let input = "\u{3}\0\0\0abc\0";
	let parser = Parser::new(&input.as_bytes());
	let (_, x) = parser.parse_string(&input.as_bytes()).unwrap();
	assert_eq!(x, "abc");
    }

    #[test]
    fn considers_alignment() {
	use Type::*;
	
	let input = "\0\0\0\0\u{4}\0\0\0";
	let parser = Parser::new(&input.as_bytes());
	let (_, x) = parser.parse_int32(&input[1..].as_bytes()).unwrap();
	assert_eq!(x, 4);
    }

    #[test]
    fn does_not_parse_incomplete_types() {
	let inputs = ["\u{2}aa", "\u{3}(ii", "\u{3}ii)"];
	for input in inputs.iter() {
	    let parser = Parser::new(&input.as_bytes());
	    let output = parser.parse_signature(&input.as_bytes());
	    dbg!(&output);
	    assert!(output.is_err())
	}
    }

    fn make_header() -> (&'static str, MessageHeader<'static>) {
	let input = "l\u{1}\u{1}\u{1}\u{0}\u{0}\u{0}\u{0}\u{7}\u{0}\u{0}\u{0}\u{1}\u{0}\u{0}\u{0}\u{1}o\0\0\u{3}\u{0}\u{0}\u{0}abc\0\0\0\0\0";
	let exp = MessageHeader {
	    endianness: Endian::Little,
	    kind: MessageType::MethodCall,
	    flags: HeaderFlags(0x01),
	    proto_version: MajorProtoVersion::V1,
	    len: 0,
	    serial: Serial(7),
	    fields: HeaderFields {
		path: Some("abc"),
		..Default::default()
	    }
	};
	(input, exp)
    }

    #[test]
    fn parses_message_headers() {
	let (input, exp) = make_header();
	let mut parser = Parser::new(&input.as_bytes());
	let (_, output) = parser.parse_header(input.as_bytes()).unwrap();
	assert_eq!(output, exp);
    }

    #[test]
    fn output_matches_input() {
	let (input, _) = make_header();
	let mut parser = Parser::new(&input.as_bytes());
	let (_, output) = parser.parse_header(input.as_bytes()).unwrap();
	let msg = Message {
	    header: output,
	    body: vec![]
	};
	let mut buf = vec![];

	crate::proto::encode::write(&mut buf, msg).unwrap();
	assert_eq!(input.as_bytes(), &buf);
    }
}
