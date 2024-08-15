use std::{
    ffi::CString,
    ptr::NonNull, 
    num::NonZeroU32, 
    thread,
    net::{
      Ipv4Addr,
      SocketAddrV4,  
    },
    str::FromStr,
    alloc::{
      alloc,
      Layout,  
    },
};

use aya::{
    Pod,
    maps::Stack,
    programs::{Xdp, XdpFlags},
    Bpf,
    include_bytes_aligned,
};

use xdpilone::{
    BufIdx, 
    IfInfo, 
    Socket, 
    SocketConfig, 
    Umem,
    UmemConfig,
    DeviceQueue,
    RingTx,
    xdp::XdpDesc,
};

use rand::{thread_rng, seq::SliceRandom};
use anyhow::{anyhow, Result};
use clap::Parser;

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    iface: String,
    #[arg(short, long, value_parser = clap::value_parser!(Hosts))]
    lhosts: Hosts,
    #[arg(short, long, default_value_t=1 << 20)]
    umem_size: usize,
    #[arg(short, long, default_value_t=1 << 20)]
    complete_size: u32,
    #[arg(short, long, default_value_t=1 << 20)]
    tx_size: u32,
    #[arg(short, long, default_value_t=1 << 12)]
    frame_size: u32,
}


fn main() -> Result<(), anyhow::Error> {
    let mut args = <Args as Parser>::parse();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    // if ret != 0 {
        // debug!("remove limit on locked memory failed, ret is: {}", ret);
    // }

    // this should never fail
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!("../../kaneru-ebpf/target/bpfel-unknown-none/debug/kaneru")).unwrap();
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!("../../kaneru-ebpf/target/bpfel-unknown-none/release/kaneru")).unwrap();

    let mut responses: Stack<_, IpPort> = Stack::try_from(bpf.take_map("RESPONSES").unwrap()).unwrap();

    let xdp: &mut Xdp = bpf
        .program_mut("receive")
        .unwrap()
        .try_into()
        .unwrap();
    xdp.load()?;
    xdp.attach(&args.iface, XdpFlags::default())?;


    let config = UmemConfig {
        fill_size: 1, // 0 doesn't work for whatever reason
        complete_size: args.complete_size,
        frame_size: args.frame_size, 
        headroom: 0,
        flags: 0,
    };
    
    let umem_size: usize = args.umem_size;
    let layout = Layout::from_size_align(umem_size, 16384).unwrap(); // page aligned, even on apple cpus
    let ptr = unsafe { NonNull::slice_from_raw_parts(NonNull::new_unchecked(alloc(layout)), umem_size) };


    // xdpilone crate author didn't bother to 
    // implement std::error::Error for Errno,
    // so we have to catch it manually every time
    let mut umem: Umem = {
        unsafe { Umem::new(config, ptr).expect("umem creation error") }
    };


    let mut iface = IfInfo::invalid();
    iface.from_name(CString::new(args.iface.clone()).unwrap().as_c_str())
        .expect("couldn't find interface");
    let sock = Socket::with_shared(&iface, &umem)
        .expect("couldn't create xsk");
    let fq_cq = umem.fq_cq(&sock)
        .expect("couldn't map fill and completion queues"); // Fill Queue / Completion Queue

    let cfg = SocketConfig {
        rx_size: None,
        tx_size: NonZeroU32::new(args.tx_size),
        bind_flags: SocketConfig::XDP_BIND_ZEROCOPY  | SocketConfig::XDP_BIND_NEED_WAKEUP,
    };
    let rxtx = umem.rx_tx(&sock, &cfg)
        .expect("couldn't map rx and tx queues"); // RX + TX Queues
    let tx = rxtx.map_tx()
        .expect("couldn't map tx queue");
    
    umem.bind(&rxtx)
        .expect("couldn't bind xsk");

    let h = thread::spawn(move || {
        for _ in 0..100 {
            loop {
                if let Ok(res) = responses.pop(0) {
                    println!("SYN-ACK FROM {:?}:{}", Ipv4Addr::from_bits(res.0.0.to_be()), u16::from_be(res.0.1)); 
                    break;
                };
            } 
        }
    });

    let length: u32 = umem_size as u32 / args.frame_size;

    prepare_buffers(&mut umem, length, &args.iface);
    send(&mut umem, length, tx, fq_cq, &mut args.lhosts);
    eprintln!("done sending packets");

    // wait for a bit and then kill the child thread
    let _= h.join();

    Ok(())
}

#[derive(Copy, Clone)]
struct IpPort((u32, u16)); // sucks that i have to do this...
unsafe impl Pod for IpPort {} // clearly, it is safe to transmute this from bytes

#[inline(always)]
fn prepare_buffers(umem: &mut Umem, len: u32, interface: &str) {
    let iface = netdev::get_interfaces().into_iter()
        .find(|i| {i.name == interface}).unwrap();
    let gateway = iface.gateway.unwrap(); // this will fail if you try to run it on, say, loopback

    // we fill out all of the fields that coincide for all packets
    for i in 0..len {
        let mut frame = umem.frame(BufIdx(i)).unwrap();
        unsafe {
            // the bulk of the packet
            let fr = &mut frame.addr.as_mut()[..54];
            fr.copy_from_slice(&SYN_PACKET[..]);
            // dst mac
            fr[0..6].copy_from_slice(&gateway.mac_addr.octets());
            // src mac
            fr[6..12].copy_from_slice(&iface.mac_addr.unwrap().octets());
            // src ip
            fr[26..30].copy_from_slice(&iface.ipv4.first().unwrap().addr.octets());
        }
    }
}

#[inline(always)]
fn finalize_buffer(addr: u64, host: &SocketAddrV4) {
    let ip = host.ip();
    let port = host.port();
    unsafe {
        let fr = std::slice::from_raw_parts_mut(addr as *mut u8, 54);
        // dst ip
        fr[30..34].copy_from_slice(&ip.to_bits().to_be_bytes());
        // ip checksum
        set_ip_chksum(&mut fr[14..34]);
        // dst tcp port
        fr[36..38].copy_from_slice(&port.to_be_bytes());
        // tcp checksum
        set_tcp_chksum(&mut fr[14..54]);
        // println!("{:?}", fr);
    }
}

#[inline(always)]
fn set_ip_chksum(header: &mut [u8]) {
    let mut sum = 0u32;
    // according to the disassembly, without this the unrolled loops end up as ten billion bounds checks, which just looks ugly
    // and I don't really want to write get_unchecked() everywhere either
    assert!(header.len() >= 20); // obviously, this never fails (we know the header length statically)
    for i in 0..5 {
        sum += u16::from_le_bytes([header[2 * i], header[2 * i + 1]]) as u32;
    }
    for i in 6..10 { 
        sum += u16::from_le_bytes([header[2 * i], header[2 * i + 1]]) as u32;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let sum = !(sum as u16);
    header[10..12].copy_from_slice(&sum.to_le_bytes());
}

// TODO: rewrite. this is horrible (but actually the pseudoheader part compiles into decent code? maybe I should leave it like this.)
#[inline(always)]
fn set_tcp_chksum(header: &mut [u8]) {
    let mut ps_header: [u8; 12] = [0; 12];
    ps_header[0..8].copy_from_slice(&header[12..20]);
    ps_header[9] = 0x06;
    ps_header[11] = 20;
    
    let mut sum = 0u32;
    for i in 0..6 {
        sum += u16::from_le_bytes([ps_header[2 * i], ps_header[2 * i + 1]]) as u32;
    }
    assert!(header.len() >= 40); 
    for i in 0..8 {
        sum += u16::from_le_bytes([header[20 + 2 * i], header[21 + 2 * i]]) as u32;
    } // ignore the previous checksum field
    for i in 9..10 {
        sum += u16::from_le_bytes([header[20 + 2 * i], header[21 + 2 * i]]) as u32;
    }

     
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    let sum = !(sum as u16);
    header[36..38].copy_from_slice(&sum.to_le_bytes());
}


// tx -(kernel)-> complete
// /\              /
//  \             /
//   \           /
//    \         /
//     \       /
// 	    \     / 
// 	     \   \/
// 	    buffers

#[inline(always)]
fn send(umem: &mut Umem, len: u32, mut tx: RingTx, mut fq_cq: DeviceQueue, hosts: &mut Hosts) {
    let base = umem.frame(BufIdx(0)).unwrap().addr.as_ptr() as *const u8 as u64;
    let mut buffers: Vec<u64> = (0..len).map(|idx| umem.frame(BufIdx(idx)).unwrap().addr.as_ptr() as *const u8 as u64 - base).collect();
    let mut host_iter = hosts.rand_iter();
    
    // having to to pointer arithmetic is very unfortunate, 
    // but both the tx and comp queues only consume and produce, respectively, the __offset__ of the frame
    // while we need its __address__ in order to write data to the buffer
    
    'm: loop { 
        while let Some(addr) = buffers.pop() { // enqueue tx
            // there is most likely some performance left on the table here, since we don't really batch transmissions
            // but profiling (at least on my fairly slow wi-fi nic) shows 
            // that the majority of the runtime is spent dequeueing, so this is probably okay for now
            if let Some(host) = host_iter.next() {
                finalize_buffer(addr + base, host);
                {
                    let mut writer = tx.transmit(1); 
                    writer.insert_once(XdpDesc { 
                        addr,
                        len: 54,
                        options: 0,
                    });
                    writer.commit();
                }
                if tx.needs_wakeup() {
                    tx.wake();
                }
            } else {
                break 'm;
            }
        }

        { // dequeue completions
            let mut reader = fq_cq.complete(fq_cq.available());
            while let Some(addr) = reader.read() {
                buffers.push(addr);
            }
            reader.release();
        }
    }
}

static SYN_PACKET: [u8; 54] = [
    // ETHER
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // (dst mac) : [0..6]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (src mac) : [6..12]
    0x08, 0x00, // proto
    
    // IP : [14..34]
    0x45, 0x00, 0x00, 0x28, // version etc 
    0x00, 0x01, 0x00, 0x00, // more irrelevant stuff
    0xFF, 0x06, // ttl, protocol
    0x00, 0x00, // [checksum] : [24..26]
    0, 0, 0, 0, // (src ip) : [26..30]
    0, 0, 0, 0, // [dst ip] : [30..34]

    // TCP [34..54]
    0x05, 0x39, // source port known statically as 1337 (this is required for the ebpf program to know which packets are to be directed to the scanner)
    0x00, 0x00, // [dst port] : [36..38]
    0x00, 0x00, 0x00, 0x00, // sequence number
    0x00, 0x00, 0x00, 0x00, // acknowledgment number
    0x50, // data offset
    0b00000010, // flags = SYN
    0x20, 0x00, // window size
    0x00, 0x00, // [checksum] : [50..52]
    0x00, 0x00, // urgent pointer
];

#[derive(Clone)]
struct Hosts {
    list: Vec<SocketAddrV4>,
}

impl Hosts {
    fn rand_iter(&mut self) -> impl Iterator<Item=&SocketAddrV4> {
        self.list.shuffle(&mut thread_rng());
        self.list.iter()
    }
}

// format: 
// ip(/mask):port(-port)(,port,...)(;...)
//
// for now this will be implemented poory: 
// -- memory usage linear in the number of ip:port pairs
// -- also this allocates a whole lot when it really should not
impl FromStr for Hosts {
    type Err = anyhow::Error;

    fn from_str(arg: &str) -> Result<Self, Self::Err> {
        let mut list = Vec::<SocketAddrV4>::new();        
        for subrange_str in arg.split(";") {
            let [subnet_str, port_ranges_str]: [&str; 2] = subrange_str
                .split(":")
                .collect::<Vec<_>>()[..]
                .try_into()?; // the format should __always__ be subnet_str:port_range_str

            let ips: Vec<Ipv4Addr> = match subnet_str.split("/").collect::<Vec<_>>()[..] {
                [ip_str] => vec![ip_str.parse()?],
                [ip_str, mask] => {
                    let m: u32 = mask.parse()?;
                    let ip: Ipv4Addr = ip_str.parse()?;
                    let bits = ip.to_bits(); 
                    let mut ips = vec![];
                    for i in 0..(1 << (32 - m)) {
                        ips.push(Ipv4Addr::from_bits(bits ^ i));
                    }
                    ips
                },
                _ => { return Err(anyhow!("bad ip/mask format")) },
            };

            let mut ports = Vec::<u16>::new();
            for port_range_str in port_ranges_str.split(",") {
                let range = match port_range_str.split("-").collect::<Vec<_>>()[..] {
                    [port] => port.parse::<u16>()?..=port.parse::<u16>()?,
                    [start, end] => start.parse::<u16>()?..=end.parse::<u16>()?,
                    _ => { return Err(anyhow!("bad port range format")) },
                };
                ports.extend(range);
            }

            for &ip in ips.iter() {
                for &port in ports.iter() {
                    list.push(SocketAddrV4::new(ip, port));
                }
            }
        }

        Ok(Self {
            list,
        })
    }
}
