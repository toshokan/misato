use misato::proto::encode::write;
use misato::proto::wire::*;

use criterion::{criterion_group, criterion_main, Criterion};

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
        },
    };
    (input, exp)
}

fn data() -> Vec<Data<'static>> {
    vec![
        Data::String("The quick brown fox will probably never stop jumping over the lazy dog"),
        Data::ObjectPath("/var/log/auth.log"),
        Data::UInt32(12312),
        Data::Boolean(true),
        Data::String("alalalalalalallajahdsuh"),
        Data::Double(3.14159),
    ]
}

fn parse_only(c: &mut Criterion) {
    let (input, exp) = make_header();
    let bytes = input.as_bytes();

    c.bench_function("parse_only", |b| {
        b.iter(|| {
            let mut parser = Parser::new(bytes);
            let (_, output) = parser.parse_header(bytes).unwrap();
            ()
        })
    });
}

fn encode_only(c: &mut Criterion) {
    let (_, exp) = make_header();
    let mut buf = vec![];

    let msg = Message {
        header: exp,
        body: data(),
    };

    c.bench_function("encode_only", |b| {
        b.iter(|| {
            write(&mut buf, &msg).unwrap();

            ()
        })
    });
}

fn parse_and_reencode(c: &mut Criterion) {
    let (input, _) = make_header();
    let bytes = input.as_bytes();
    let mut buf = vec![];

    c.bench_function("parse_and_reencode", |b| {
        b.iter(|| {
            let mut parser = Parser::new(bytes);
            let (_, output) = parser.parse_header(bytes).unwrap();

            let msg = Message {
                header: output,
                body: vec![],
            };

            write(&mut buf, &msg).unwrap();

            buf.clear();

            ()
        })
    });
}

criterion_group!(benches, parse_and_reencode, parse_only, encode_only);
criterion_main!(benches);
