extern crate libc;
extern crate errno;

use std::io::Write;

const ETH_P_ARP: libc::c_int = 0x0806;

fn main() {
    let mut args = std::env::args();
    if args.len() != 3 {
        std::io::stderr().write("Usage: arpmasqd LISTEN_ADDR SEND_ADDR\n".as_ref()).unwrap();
        panic!("number of arguments");
    }
    let listen_addr = args.next();
    let send_addr = args.next();
    let listen_socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ARP.to_be()) };
    if listen_socket == -1 {
        let err = errno::errno();
        panic!("Error opening socket: {} ({})", err, err.0);
    }
    let bind_result = unsafe { libc::bind(listen_socket, &listen_sockaddr, std::mem::size_of_val(listen_sockaddr)) };
    if bind_result == -1 {
        let err = errno::errno();
        panic!("Error binding socket: {} ({})", err, err.0);
    }
}
