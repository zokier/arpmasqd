#![feature(slice_bytes,clone_from_slice)]

extern crate libc;
extern crate errno;
extern crate rustc_serialize; //debug hex dump

#[macro_use]
extern crate nom;

use std::io::Write;
use rustc_serialize::hex::ToHex;

const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;
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

#[derive(Debug)]
struct EthernetFrame {
    dst: MacAddr,
    src: MacAddr,
    ty: EthernetType,
    payload: EthernetPayload,
}

#[derive(Debug)]
struct MacAddr([u8; 6]);
impl MacAddr {
    fn from_slice(s: &[u8]) -> MacAddr {
        // bit ugly, is there a better way?
        let mut m = MacAddr([0u8; 6]);
        m.0.clone_from_slice(s);
        return m;
    }
}
#[derive(Debug)]
struct IpAddr(u32);

#[derive(Debug)]
#[repr(u16)]
enum EthernetType {
    Arp = ETH_P_ARP,
    Ip = ETH_P_IP
}

#[derive(Debug)]
enum EthernetPayload {
    Arp(ArpPacket),
}

#[derive(Debug)]
struct ArpPacket {
    hwtype: u16,
    proto: u16,
    hwsize: u8,
    protosize: u8,
    opcode: u16,
    sender_mac: MacAddr,
    sender_ip: IpAddr,
    target_mac: MacAddr,
    target_ip: IpAddr
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

fn u16_to_be_bytes(i: u16) -> [u8;2] {
    [((i>>8) & 0xff) as u8, (i & 0xff) as u8]
}

named!(arp_packet_parser(&[u8]) -> ArpPacket, chain!(
    hwtype: call!(nom::be_u16)
    ~ proto: call!(nom::be_u16)
    ~ hwsize: call!(nom::be_u8)
    ~ protosize: call!(nom::be_u8)
    ~ opcode: call!(nom::be_u16)
    ~ sender_mac: take!(6)
    ~ sender_ip: call!(nom::be_u32)
    ~ target_mac: take!(6)
    ~ target_ip: call!(nom::be_u32),
    || {
        ArpPacket {
            hwtype: hwtype,
            proto: proto,
            hwsize: hwsize,
            protosize: protosize,
            opcode: opcode,
            sender_mac: MacAddr::from_slice(sender_mac),
            sender_ip: IpAddr(sender_ip),
            target_mac: MacAddr::from_slice(target_mac),
            target_ip: IpAddr(target_ip)
        }
    })
);

named!(eth_frame_parser(&[u8]) -> EthernetFrame, chain!(
    dst: take!(6)
    ~ src: take!(6)
    ~ _ty: tag!(u16_to_be_bytes(ETH_P_ARP))
    ~ payload: call!(arp_packet_parser),
    || {
        EthernetFrame {
            dst: MacAddr::from_slice(dst),
            src: MacAddr::from_slice(src),
            ty: EthernetType::Arp,
            payload: EthernetPayload::Arp(payload)
        }
    })
);

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
        //TODO minimum arp packet length?
        if recv_result >= 42 {
            if let nom::IResult::Done(_, frame) = eth_frame_parser(&buf[0..(recv_result as usize)]) {
                println!("{:?}", frame);
            } else {
                println!("parser error");
            }
        } else {
            println!("Too short frame ({}): {}", recv_result, buf[0..(recv_result as usize)].to_hex());
        }
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
