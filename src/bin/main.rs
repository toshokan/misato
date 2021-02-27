// use libc::sockaddr_un;
use std::io::BufRead;
use std::io::Result;
// use std::os::unix::net::UnixStream;

// fn unix_abstract_socket_connect(name: &[u8]) -> Result<UnixStream> {
//     use std::os::unix::io::FromRawFd;

//     let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
//     let mut addr: sockaddr_un = unsafe { std::mem::zeroed() };

//     addr.sun_family = libc::AF_UNIX as u16;

//     if name.len() > addr.sun_path.len() - 1 {
// 	Err(Error::from(ErrorKind::InvalidData))?
//     }

//     let size = std::mem::size_of::<sockaddr_un>() - (addr.sun_path.len() - name.len()) + 1;
//     let size = size as u32;

//     let r = unsafe {
// 	let src = name.as_ptr() as *const libc::c_char;
// 	let dest = addr.sun_path[1..].as_mut_ptr() as *mut libc::c_char;
// 	std::ptr::copy(src, dest, name.len());
// 	libc::connect(fd,
// 		      &addr as *const _ as *const libc::sockaddr,
// 		      size)
//     };

//     if r != 0 {
// 	Err(std::io::Error::last_os_error())?
//     }

//     Ok(unsafe { UnixStream::from_raw_fd(fd) })
// }

fn main() -> Result<()> {
    // use std::io::{Read, Write, BufRead};
    // let sock = unix_abstract_socket_connect("/tmp/dbus-pHJaVVvY7H".as_bytes())?;

    // let (r, mut w) = (&sock, &sock);
    // let mut reader = std::io::BufReader::new(r);

    // w.write(b"\0")?;
    // w.write(b"AUTH EXTERNAL 31303030\r\n")?;

    // let mut buf = String::new();
    // reader.read_line(&mut buf)?;
    // eprintln!("{:?}", buf);
    // buf.clear();

    // w.write(b"NEGOTIATE_UNIX_FD\r\n")?;
    // reader.read_line(&mut buf)?;
    // eprintln!("{:?}", buf);
    // buf.clear();

    // w.write(b"BEGIN\r\n")?;
    // reader.read_line(&mut buf)?;
    // eprintln!("{:?}", buf);
    let stdin = std::io::stdin();
    let stdin = stdin.lock();

    for line in stdin.lines() {
        if let Ok(line) = line {
            let mut parser = misato::proto::wire::Parser::new(&line.as_bytes());
            let (_, header) = parser.parse_header(&line.as_bytes()).unwrap();
            let msg = misato::proto::wire::Message {
                header,
                body: vec![],
            };
            misato::proto::encode::write(std::io::stdout(), &msg).unwrap();
        }
    }

    Ok(())
}
