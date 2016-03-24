#![feature(box_syntax,slice_patterns)]

extern crate libc;
extern crate errno;
extern crate rustc_serialize; //debug hex dump

#[macro_use]
extern crate nom;

use std::io::Write;
use rustc_serialize::hex::ToHex;

#[cfg(target_env = "gnu")]
#[allow(non_camel_case_types)]
type ioctl_request_t = libc::c_ulong;
#[cfg(target_env = "musl")]
#[allow(non_camel_case_types)]
type ioctl_request_t = libc::c_int;

const ETH_P_ALL: u16 = 0x0003;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const IFNAMSIZ: usize = 16; // net/if.h
const SIOCGIFADDR: ioctl_request_t = 0x8915;
const SIOCGIFNETMASK: ioctl_request_t = 0x891b;
const SIOCGIFHWADDR: ioctl_request_t = 0x8927;
const SIOCGIFINDEX: ioctl_request_t = 0x8933;
const RECV_BUF_LEN: usize = 1522;
const SO_ATTACH_FILTER: libc::c_int = 26;
const SOCK_SEQPACKET: libc::c_int = 5;

#[repr(C)]
#[allow(non_camel_case_types)]
struct sock_filter { /* Filter block */
    code: u16,       /* Actual filter code */
    jt: u8,          /* Jump true */
    jf: u8,          /* Jump false */
    k: u32           /* Generic multiuse field */
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct sock_fprog {     /* Required for SO_ATTACH_FILTER. */
    len: u16,           /* Number of filter blocks */
    filter: *const sock_filter
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq_ifhwaddr {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifhwaddr: libc::sockaddr
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq_ifaddr {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifaddr: libc::sockaddr_in
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq_ifindex {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifindex: libc::c_int
}

#[derive(Debug)]
struct EthernetFrame {
    dst: MacAddr,
    src: MacAddr,
    tag: Option<VlanTag>,
    tysize: EthernetTypeSize,
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

impl std::fmt::Display for MacAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               self.0[0], self.0[1], self.0[2],
               self.0[3], self.0[4], self.0[5])
    }
}

#[derive(Debug)]
struct VlanTag(u16);

#[derive(Debug,Copy,Clone)]
struct IpAddr(u32);

impl std::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}",
               (self.0 >> 24) & 0xff, (self.0 >> 16) & 0xff,
               (self.0 >> 8) & 0xff, self.0 & 0xff)
    }
}

#[derive(Debug)]
#[repr(u16)]
enum EtherType {
    Arp = ETH_P_ARP,
    _Ip = ETH_P_IP
}

#[derive(Debug)]
enum EthernetTypeSize {
    Size(u16),
    Type(EtherType),
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

#[derive(Debug)]
struct SocketError { 
    action: &'static str,
    err: errno::Errno
}

macro_rules! sockerr {
    ($action:expr, $res:expr) => {
        if $res == -1 {
            return Err(SocketError{ action: $action, err: errno::errno() });
        }
    };
}

fn ifhwaddr_from_ifname(ifname: &str, sock: libc::c_int) -> Result<MacAddr, SocketError> {
    let mut ifr = ifreq_ifhwaddr {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifhwaddr: unsafe { std::mem::zeroed() }
    };
    ifr.ifr_name.as_mut().write(ifname.as_bytes()).unwrap();
    let res = unsafe { libc::ioctl(sock, SIOCGIFHWADDR, &ifr) };
    sockerr!("getting ifhwaddr", res);
    unsafe {
    return Ok(MacAddr::from_slice(std::mem::transmute(&ifr.ifr_ifhwaddr.sa_data[0..6])));
    }
}

fn swap_endianess(i: u32) -> u32 {
    ((i >> 24) & 0xFF) | (((i >> 16) & 0xFF) << 8) | (((i >> 8) & 0xFF) << 16) | ((i & 0xFF) << 24)
}

fn ifnetmask_from_ifname(ifname: &str, sock: libc::c_int) -> Result<IpAddr, SocketError> {
    let mut ifr = ifreq_ifaddr {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifaddr: unsafe { std::mem::zeroed() }
    };
    ifr.ifr_name.as_mut().write(ifname.as_bytes()).unwrap();
    let res = unsafe { libc::ioctl(sock, SIOCGIFNETMASK, &ifr) };
    sockerr!("getting ifaddr", res);
    return Ok(IpAddr(swap_endianess(ifr.ifr_ifaddr.sin_addr.s_addr)));
}

fn ifaddr_from_ifname(ifname: &str, sock: libc::c_int) -> Result<IpAddr, SocketError> {
    let mut ifr = ifreq_ifaddr {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifaddr: unsafe { std::mem::zeroed() }
    };
    ifr.ifr_name.as_mut().write(ifname.as_bytes()).unwrap();
    let res = unsafe { libc::ioctl(sock, SIOCGIFADDR, &ifr) };
    sockerr!("getting ifaddr", res);
    return Ok(IpAddr(swap_endianess(ifr.ifr_ifaddr.sin_addr.s_addr)));
}

fn ifindex_from_ifname(ifname: &str, sock: libc::c_int) -> Result<libc::c_int, SocketError> {
    let mut ifr = ifreq_ifindex {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifindex: 0
    };
    ifr.ifr_name.as_mut().write(ifname.as_bytes()).unwrap();
    let res = unsafe { libc::ioctl(sock, SIOCGIFINDEX, &ifr) };
    sockerr!("getting ifindex", res);
    return Ok(ifr.ifr_ifindex);
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

    let listen_socket = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32)
    };
    sockerr!("opening socket", listen_socket);
    let attach_filter_res = unsafe {
        libc::setsockopt(
            listen_socket,
            libc::SOL_SOCKET,
            SO_ATTACH_FILTER,
            std::mem::transmute(&bpf_filter_arp_incoming_prog),
            std::mem::size_of_val(&bpf_filter_arp_incoming_prog) as u32
        )
    };
    sockerr!("attaching filter", attach_filter_res);

    let ifindex = try!(ifindex_from_ifname(&iface, listen_socket));

    let listen_sockaddr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: ETH_P_ALL.to_be(),
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8]
    };
    let bind_result = unsafe {
        libc::bind(
            listen_socket,
            std::mem::transmute(&listen_sockaddr),
            std::mem::size_of_val(&listen_sockaddr) as u32
        )
    };
    sockerr!("binding socket", bind_result);
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

fn tysize_parser(input: &[u8]) -> nom::IResult<&[u8], EthernetTypeSize> {
    match nom::be_u16(input) {
        nom::IResult::Done(i,tysize) => {
            if tysize == ETH_P_ARP {
                nom::IResult::Done(i,EthernetTypeSize::Type(EtherType::Arp))
            } else if tysize < 0x0600 {
                nom::IResult::Done(i,EthernetTypeSize::Size(tysize))
            } else {
                //TODO better error code
                nom::IResult::Error(nom::Err::Code(nom::ErrorKind::Custom(1)))
            }
        },
        nom::IResult::Error(err) => nom::IResult::Error(err),
        nom::IResult::Incomplete(need) => nom::IResult::Incomplete(need)
    }
}

named!(eth_frame_parser(&[u8]) -> EthernetFrame, chain!(
    dst: take!(6)
    ~ src: take!(6)
    ~ tag: opt!(
        chain!(
            _tpid: tag!(u16_to_be_bytes(0x8100))
            ~ tci: call!(nom::be_u16),
            || {
                VlanTag(tci)
            }
        )
    )
    ~ tysize: call!(tysize_parser)
    ~ payload: call!(arp_packet_parser),
    || {
        EthernetFrame {
            dst: MacAddr::from_slice(dst),
            src: MacAddr::from_slice(src),
            tag: tag,
            tysize: tysize,
            payload: EthernetPayload::Arp(payload)
        }
    })
);

fn netmap_ip(src: IpAddr, dst: IpAddr, mask: IpAddr) -> IpAddr {
    IpAddr((src.0 & !mask.0) | (dst.0 & mask.0))
}

struct LinkInfo {
    ifname: String,
    ifindex: libc::c_int,
    addr: IpAddr,
    mask: IpAddr,
    hwaddr: MacAddr,
    send_socket: libc::c_int,
}

fn create_send_socket() -> Result<libc::c_int, SocketError> {
    let send_socket = unsafe {
        libc::socket(libc::AF_PACKET, libc::SOCK_RAW, ETH_P_ALL.to_be() as i32)
    };
    sockerr!("opening socket", send_socket);

    return Ok(send_socket);
}

impl LinkInfo {
    fn new(ifname: &str) -> LinkInfo {
        let sock = create_send_socket().unwrap();
        LinkInfo {
            ifname: ifname.to_owned(),
            ifindex: ifindex_from_ifname(ifname, sock).unwrap(),
            addr: ifaddr_from_ifname(ifname, sock).unwrap(),
            mask: ifnetmask_from_ifname(ifname, sock).unwrap(),
            hwaddr: ifhwaddr_from_ifname(ifname, sock).unwrap(),
            send_socket: sock,
        }
    }
}

fn handle_arp_from_right(eth_frame: &EthernetFrame, left_info: &LinkInfo) {
    let EthernetPayload::Arp(ref arp_packet) = eth_frame.payload;
    if arp_packet.hwtype == 1
        && arp_packet.proto == ETH_P_IP
        && arp_packet.hwsize == 6
        && arp_packet.protosize == 4
        && arp_packet.opcode == 2 //response
    {
        println!("send to {} ARP response from {} is-at {}", left_info.ifname, netmap_ip(arp_packet.sender_ip, left_info.addr, left_info.mask), left_info.hwaddr);
    }
}

fn handle_arp_from_left(eth_frame: &EthernetFrame, right_info: &LinkInfo) {
    let EthernetPayload::Arp(ref arp_packet) = eth_frame.payload;
    if arp_packet.hwtype == 1
        && arp_packet.proto == ETH_P_IP
        && arp_packet.hwsize == 6
        && arp_packet.protosize == 4
        && arp_packet.opcode == 1 //request
    {
        println!("send to {} ARP request: from {} ({}) who-has {}?", right_info.ifname, right_info.hwaddr, right_info.addr, netmap_ip(arp_packet.target_ip, right_info.addr, right_info.mask));
    }
}

fn do_recv(listen_socket: libc::c_int, ctrl_socket: libc::c_int, handle_arp_packet: fn(&EthernetFrame, &LinkInfo), link_info: LinkInfo) -> SocketError
{
    let buf = [0u8; RECV_BUF_LEN];
    let mut recv_sockaddr = unsafe { std::mem::zeroed::<libc::sockaddr_ll>() };
    let mut recv_sockaddr_len: u32 = std::mem::size_of_val(&recv_sockaddr) as u32;
    let readfds: *mut libc::fd_set = std::boxed::Box::into_raw(unsafe {
        box std::mem::zeroed::<libc::fd_set>()
    });
    let writefds: *mut libc::fd_set = std::ptr::null_mut();
    let exceptfds: *mut libc::fd_set = std::ptr::null_mut();
    let timeout: *mut libc::timeval = std::ptr::null_mut();
    let nfds: libc::c_int = std::cmp::max(listen_socket, ctrl_socket) + 1;
    loop {
        let recv_result = unsafe {
            libc::FD_ZERO(readfds);
            libc::FD_SET(ctrl_socket, readfds);
            libc::FD_SET(listen_socket, readfds);
            let select_result = libc::select(nfds, readfds, writefds, exceptfds, timeout);
            if select_result == -1 {
                return SocketError { action: "select", err: errno::errno() };
            }
            if libc::FD_ISSET(ctrl_socket, readfds) {
                return SocketError { action: "FD_ISSET(ctrl_socket)", err: errno::errno() };
            }
            if !libc::FD_ISSET(listen_socket, readfds) {
                return SocketError { action: "!FD_ISSET(listen_socket)", err: errno::errno() };
            }
            libc::recvfrom(
                listen_socket,
                std::mem::transmute(&buf),
                RECV_BUF_LEN,
                0,
                std::mem::transmute(&mut recv_sockaddr),
                &mut recv_sockaddr_len
            )
        };
        if recv_result == -1 {
            return SocketError { action: "recvfrom", err: errno::errno() };
        }
        // rust has no offsetof yet so we hardcode 12 here instead
        // println!("From: {}", recv_sockaddr.sll_addr[0..(recv_sockaddr_len as usize -12)].to_hex());
        //TODO minimum arp packet length?
        if recv_result >= 42 {
            match eth_frame_parser(&buf[0..(recv_result as usize)]) {
                nom::IResult::Done(_i, frame) => handle_arp_packet(&frame, &link_info),
                nom::IResult::Error(err) => println!("Parser error: {:?}", err),
                nom::IResult::Incomplete(needed) => println!("Parser incomplete: {:?}", needed)
            }
        } else {
            println!("Too short frame ({}): {}", recv_result, buf[0..(recv_result as usize)].to_hex());
        }
    }
}

struct Worker<T> {
    thread: std::thread::JoinHandle<T>,
}

fn create_worker(iface: &str, ctrl_socket: libc::c_int, callback: fn(&EthernetFrame, &LinkInfo), link_info: LinkInfo) -> Result<Worker<SocketError>, SocketError>
{
    let thread = match create_listen_socket(&iface) {
        Ok(sock) => std::thread::spawn(move || {
            let ret = do_recv(sock, ctrl_socket, callback, link_info);
            unsafe { libc::write(ctrl_socket, std::mem::transmute(&'\0'), 1) };
            return ret;
        }),
        Err(err) => {
            std::io::stderr().write(format!("Error {}: {} ({})\n", err.action, err.err, err.err.0).as_ref()).unwrap();
            return Err(err);
        }
    };
    return Ok(Worker { thread: thread })
}

fn main_wrapper() -> i32 {
    let mut args = std::env::args();
    if args.len() != 3 {
        std::io::stderr().write("Usage: arpmasqd LEFT_IFACE RIGHT_IFACE\n".as_ref()).unwrap();
        return 1;
    }
    args.next();

    let [left_ctrl, right_ctrl] = unsafe {
        let mut socks: [libc::c_int;2] = [0,0];
        libc::socketpair(libc::AF_UNIX, SOCK_SEQPACKET, 0, socks.as_mut_ptr());
        socks
    };

    //unwrap is ok because arg count has been checked
    let left_iface = args.next().unwrap();
    let right_iface = args.next().unwrap();
    let left_info = LinkInfo::new(&left_iface);
    let right_info = LinkInfo::new(&right_iface);
    let left_worker = match create_worker(&left_iface, left_ctrl, handle_arp_from_left, right_info) {
        Ok(worker) => worker,
        Err(err) => panic!("TODO")
    };
    let right_worker = match create_worker(&right_iface, right_ctrl, handle_arp_from_right, left_info) {
        Ok(worker) => worker,
        Err(err) => panic!("TODO")
    };

    match left_worker.thread.join() {
        Ok(err) => {
            std::io::stderr().write(format!("Error {}: {} ({})\n", err.action, err.err, err.err.0).as_ref()).unwrap();
        },
        Err(err) => {
            std::io::stderr().write(format!("Panic {:?}\n", err).as_ref()).unwrap();
        }
    }
    match right_worker.thread.join() {
        Ok(err) => {
            std::io::stderr().write(format!("Error {}: {} ({})\n", err.action, err.err, err.err.0).as_ref()).unwrap();
        },
        Err(err) => {
            std::io::stderr().write(format!("Panic {:?}\n", err).as_ref()).unwrap();
        }
    }
    return 1;
}

fn main() {
    std::process::exit(main_wrapper());
}
