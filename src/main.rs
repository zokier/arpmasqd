#![feature(slice_bytes)]

extern crate libc;
extern crate errno;

use std::io::Write;

const ETH_P_ARP: u16 = 0x0806;
const IFNAMSIZ: usize = 16; // net/if.h
const SIOCGIFINDEX: libc::c_int = 0x8933;
const RECV_BUF_LEN: usize = 1500;

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

fn main() {
    let mut args = std::env::args();
    if args.len() != 3 {
        std::io::stderr().write("Usage: arpmasqd LISTEN_ADDR SEND_ADDR\n".as_ref()).unwrap();
        panic!("number of arguments");
    }
    args.next();
    //unwrap is ok because arg count has been checked
    let listen_iface = args.next().unwrap();
    let send_addr = args.next().unwrap();
    let listen_socket = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ARP.to_be() as i32) };
    if listen_socket == -1 {
        let err = errno::errno();
        panic!("Error opening socket: {} ({})", err, err.0);
    }
    let listen_sockaddr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: ETH_P_ARP.to_be(),
        sll_ifindex: ifindex_from_ifname(&listen_iface, listen_socket),
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8]
    };
    let bind_result = unsafe { libc::bind(listen_socket, std::mem::transmute(&listen_sockaddr), std::mem::size_of_val(&listen_sockaddr) as u32) };
    if bind_result == -1 {
        let err = errno::errno();
        panic!("Error binding socket: {} ({})", err, err.0);
    }

    let buf = [0u8; RECV_BUF_LEN];
    let recv_sockaddr = unsafe { std::mem::zeroed::<libc::sockaddr_ll>() };
    let mut recv_sockaddr_len: u32 = std::mem::size_of_val(&recv_sockaddr) as u32;
    let recv_result = unsafe { libc::recvfrom(listen_socket, std::mem::transmute(&buf), RECV_BUF_LEN as u64, 0, std::mem::transmute(&recv_sockaddr), &mut recv_sockaddr_len) };
    if recv_result == -1 {
        let err = errno::errno();
        panic!("Error in recvfrom: {} ({})", err, err.0);
    }
}
