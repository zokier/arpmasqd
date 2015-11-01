#![feature(slice_bytes)]

extern crate libc;
extern crate errno;
extern crate rustc_serialize; //debug hex dump

use std::io::Write;
use rustc_serialize::hex::ToHex;

const ETH_P_ALL: u16 = 0x0003;
const ETH_P_ARP: u16 = 0x0806;
const IFNAMSIZ: usize = 16; // net/if.h
const SIOCGIFINDEX: libc::c_int = 0x8933;
const RECV_BUF_LEN: usize = 1542; 
const SO_ATTACH_FILTER: libc::c_int = 26;

#[repr(C)]
#[allow(non_camel_case_types)]
struct sock_filter {	/* Filter block */
	code: u16,   /* Actual filter code */
	jt: u8,	/* Jump true */
	jf: u8,	/* Jump false */
	k: u32      /* Generic multiuse field */
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug)]
struct sock_fprog {     /* Required for SO_ATTACH_FILTER. */
        len: u16,    /* Number of filter blocks */
        filter: *const sock_filter
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifindex: libc::c_int
}

fn ifindex_from_ifname(ifname: &str, sock: libc::c_int) -> libc::c_int {
    let mut ifr = ifreq {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifindex: 0
    };
    std::slice::bytes::copy_memory(ifname.as_bytes(), &mut ifr.ifr_name);
    if unsafe { libc::funcs::bsd44::ioctl(sock, SIOCGIFINDEX, &ifr) } == -1 {
        let err = errno::errno();
        panic!("Error getting ifindex: {} ({})", err, err.0);
    }
    return ifr.ifr_ifindex;

}

struct SocketError { 
    action: &'static str,
    err: errno::Errno
}

macro_rules! sockerr {
    ($action:expr) => {
        return Err(SocketError{ action: $action, err: errno::errno() });
    };
}

fn create_listen_socket(iface: &str) -> Result<libc::c_int, SocketError> {
    // tcpdump -dd arp and incoming
    let bpf_filter_arp_incoming: [sock_filter; 6] = [
        sock_filter { code: 0x28, jt: 0, jf: 0, k: 0x0000000c },
        sock_filter { code: 0x15, jt: 0, jf: 3, k: 0x00000806 },
        sock_filter { code: 0x28, jt: 0, jf: 0, k: 0xfffff004 },
        sock_filter { code: 0x15, jt: 1, jf: 0, k: 0x00000004 },
        sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00040000 },
        sock_filter { code: 0x06, jt: 0, jf: 0, k: 0x00000000 },
    ];
    let bpf_filter_arp_incoming_prog: sock_fprog = sock_fprog {
        len: 6,
        filter: bpf_filter_arp_incoming.as_ptr()
    };

    let listen_socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32) };
    if listen_socket == -1 {
        println!("try: sudo setcap CAP_NET_RAW+eip arpmasqd");
        sockerr!("opening socket");
    }
    let attach_filter_res = unsafe { libc::setsockopt(listen_socket, libc::SOL_SOCKET, SO_ATTACH_FILTER, std::mem::transmute(&bpf_filter_arp_incoming_prog), std::mem::size_of_val(&bpf_filter_arp_incoming_prog) as u32) };
    if attach_filter_res == -1 {
        sockerr!("attaching filter");
    }
    let listen_sockaddr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: ETH_P_ALL.to_be(),
        sll_ifindex: ifindex_from_ifname(&iface, listen_socket),
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8]
    };
    let bind_result = unsafe { libc::bind(listen_socket, std::mem::transmute(&listen_sockaddr), std::mem::size_of_val(&listen_sockaddr) as u32) };
    if bind_result == -1 {
        sockerr!("binding socket");
    }
    return Ok(listen_socket);
}

fn do_recv(listen_socket: libc::c_int) -> ! {
    let buf = [0u8; RECV_BUF_LEN];
    let mut recv_sockaddr = unsafe { std::mem::zeroed::<libc::sockaddr_ll>() };
    let mut recv_sockaddr_len: u32 = std::mem::size_of_val(&recv_sockaddr) as u32;
    loop {
        let recv_result = unsafe { libc::recvfrom(listen_socket, std::mem::transmute(&buf), RECV_BUF_LEN as u64, 0, std::mem::transmute(&recv_sockaddr), &mut recv_sockaddr_len) };
        if recv_result == -1 {
            let err = errno::errno();
            panic!("Error in recvfrom: {} ({})", err, err.0);
        }
        // rust has no offsetof yet so we hardcode 12 here instead
        println!("From: {}", recv_sockaddr.sll_addr[0..(recv_sockaddr_len as usize -12)].to_hex());
        println!("Data: {}", buf[0..(recv_result as usize)].to_hex());
    }
}

fn main() {
    let mut args = std::env::args();
    if args.len() != 2 {
        std::io::stderr().write("Usage: arpmasqd LISTEN_IFACE\n".as_ref()).unwrap();
        panic!("number of arguments");
    }
    args.next();
    //unwrap is ok because arg count has been checked
    let listen_iface = args.next().unwrap();
    let listen_socket = create_listen_socket(&listen_iface).unwrap_or_else(|err| panic!("Error {}: {} ({})", err.action, err.err, err.err.0));

    do_recv(listen_socket);
}
