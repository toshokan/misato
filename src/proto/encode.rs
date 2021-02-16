use super::wire::*;
use std::io::Write;

struct BufOutputStream<W> {
    inner: W,
    header_buf: OutputBuf,
    body_buf: OutputBuf,
}

impl<W> std::fmt::Debug for BufOutputStream<W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufOutputStream")
            .field("header", &self.header_buf)
            .field("body", &self.body_buf)
            .finish()
    }
}

macro_rules! impl_numeric_write {
    ($(($ty: ty, $name: ident, $alignment: expr));*) => {
	$(
	    fn $name(&mut self, val: $ty) {
		self.align_at($alignment);
		self.buf.extend_from_slice(&val.to_le_bytes());
	    }
	)*
    }
}

struct OutputBuf {
    buf: Vec<u8>,
}

impl std::fmt::Debug for OutputBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutputBuf")
            .field("len", &self.buf.len())
            .field("data", &self.buf)
            .finish()
    }
}

impl OutputBuf {
    fn new() -> Self {
        let buf = Vec::with_capacity(4096);
        Self { buf }
    }

    fn write_header(&mut self, header: MessageHeader<'_>, body_len: u32) {
        fn endianness_as_byte(e: Endian) -> u8 {
            match e {
                Endian::Big => b'B',
                Endian::Little => b'l',
            }
        }

        fn kind_as_byte(t: MessageType) -> u8 {
            match t {
                MessageType::Invalid => 0,
                MessageType::MethodCall => 1,
                MessageType::MethodReturn => 2,
                MessageType::Error => 3,
                MessageType::Signal => 4,
            }
        }

        self.write_byte(endianness_as_byte(header.endianness));
        self.write_byte(kind_as_byte(header.kind));
        self.write_byte(header.flags.as_u8());
        self.write_byte(1);
        self.write_u32(body_len);
        self.write_u32(header.serial.as_u32());
        self.write_header_fields(&header.fields);
    }

    fn write_header_fields(&mut self, fields: &HeaderFields<'_>) {
        macro_rules! count_fields {
	    ($($f: expr),*) => {{
		let mut count: u32 = 0;
		$(
		    if let Some(_) = $f {
			count += 1;
		    }
		)*;
		count
	    }}
	}
        macro_rules! write_fields {
	    ($(($f: expr, $tag: expr, $ty: expr, $handler_fn: ident));*) => {{
		$(
		    if let Some(x) = $f {
			self.write_byte($tag);
			self.write_ty(&$ty);
			self.$handler_fn(x);
		    }
		)*
	    }}
	}
        let count = count_fields!(
            fields.path,
            fields.interface,
            fields.member,
            fields.error_name,
            fields.reply_serial,
            fields.destination,
            fields.sender,
            fields.signature,
            fields.unix_fds
        );
        self.write_u32(count);

        write_fields!(
            (fields.path, 1, Type::ObjectPath, write_str);
            (fields.interface, 2, Type::String, write_str);
            (fields.member, 3, Type::String, write_str);
            (fields.error_name, 4, Type::String, write_str);
            (fields.reply_serial, 5, Type::UInt32, write_u32);
            (fields.destination, 6, Type::String, write_str);
            (fields.sender, 7, Type::String, write_str);
            (&fields.signature, 8, Type::Signature, write_signature);
            (fields.unix_fds, 9, Type::UInt32, write_u32)
        )
    }

    impl_numeric_write!((i16, write_i16, 2);
            (u16, write_u16, 2);
            (i32, write_i32, 4);
            (u32, write_u32, 4);
            (i64, write_i64, 8);
            (u64, write_u64, 8);
            (f64, write_f64, 8)
    );

    fn write_str(&mut self, s: &str) {
        let len: u32 = s.len() as u32;
        self.write_u32(len);
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(b'\0')
    }

    #[inline]
    fn align_at(&mut self, bytes: usize) {
        static PADDING: &[u8; 8] = &[b'\0'; 8];

        let offset = self.buf.len();
        let rem = offset % bytes;
        if rem != 0 {
            self.buf.extend_from_slice(&PADDING[0..(bytes - rem)]);
        }
    }

    #[inline]
    fn write_byte(&mut self, b: u8) {
        self.buf.push(b)
    }

    fn write_ty(&mut self, t: &Type) {
        use Type::*;
        match t {
            Invalid => unimplemented!(),
            Byte => self.write_byte(b'b'),
            Boolean => self.write_byte(b'y'),
            Int16 => self.write_byte(b'n'),
            UInt16 => self.write_byte(b'q'),
            Int32 => self.write_byte(b'i'),
            UInt32 => self.write_byte(b'u'),
            Int64 => self.write_byte(b'x'),
            UInt64 => self.write_byte(b't'),
            Double => self.write_byte(b'd'),
            String => self.write_byte(b's'),
            ObjectPath => self.write_byte(b'o'),
            Signature => self.write_byte(b'g'),
            Array(t) => {
                self.write_byte(b'a');
                self.write_ty(t)
            }
            Struct(ts) => {
                self.write_byte(b'(');
                self.write_signature(ts);
                self.write_byte(b')');
            }
            Variant => self.write_byte(b'v'),
            DictEntry(k, v) => {
                self.write_byte(b'{');
                self.write_ty(k);
                self.write_ty(v);
                self.write_byte(b'}');
            }
            UnixFd => self.write_byte(b'h'),
        }
    }

    fn write_signature(&mut self, tys: &[Type]) {
        for ty in tys {
            self.write_ty(ty);
        }
    }

    pub fn write_data(&mut self, data: &Data<'_>) {
        use Data::*;
        match data {
            Invalid => unimplemented!(),
            Byte(b) => self.buf.push(*b),
            Boolean(b) => {
                let val = if *b { 1_u32 } else { 0 };
                self.write_u32(val);
            }
            Int16(i) => self.write_i16(*i),
            UInt16(u) => self.write_u16(*u),
            Int32(i) => self.write_i32(*i),
            UInt32(u) => self.write_u32(*u),
            Int64(i) => self.write_i64(*i),
            UInt64(u) => self.write_u64(*u),
            Double(d) => self.write_f64(*d),
            String(s) => self.write_str(s),
            ObjectPath(p) => self.write_str(p),
            Signature(tys) => self.write_signature(&tys),
            Array(ds) => {
                self.write_u32(ds.len() as u32);
                for d in ds {
                    self.write_data(d);
                }
            }
            Struct(ds) => {
                self.align_at(8);
                for d in ds {
                    self.write_data(d);
                }
            }
            Variant(t, d) => {
                self.write_ty(t);
                self.write_data(d);
            }
            DictEntry(k, v) => {
                self.align_at(8);
                self.write_data(k);
                self.write_data(v);
            }
            UnixFd(fd) => self.write_u32(*fd),
        }
    }
}

impl<W: Write> BufOutputStream<W> {
    fn new(inner: W) -> Self {
        let header_buf = OutputBuf::new();
        let body_buf = OutputBuf::new();
        Self {
            inner,
            header_buf,
            body_buf,
        }
    }
}

pub fn write(os: impl Write, message: Message<'_>) -> std::io::Result<()> {
    let mut os = BufOutputStream::new(os);

    let (header, body) = message.into_parts();

    for data in body {
        os.body_buf.write_data(&data);
    }

    os.header_buf
        .write_header(header, os.body_buf.buf.len() as u32);
    os.header_buf.align_at(8);

    dbg!(&os);

    os.inner.write_all(&os.header_buf.buf)?;
    os.inner.write_all(&os.body_buf.buf)?;

    Ok(())
}
