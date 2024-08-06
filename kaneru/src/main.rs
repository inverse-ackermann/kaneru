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

use netdev;
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


// tx -(kernel)-> complete
// /\              /
//  \             /
//   \           /
//    \         /
//     \       /
// 	    \     / 
// 	     \   \/
// 	      queue

fn main() -> Result<(), anyhow::Error> {
    let mut args = <Args as Parser>::parse();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
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
    let layout = Layout::from_size_align(umem_size, 16384).unwrap(); // page aligned
    let ptr = unsafe { NonNull::slice_from_raw_parts(NonNull::new_unchecked(alloc(layout)), umem_size) };


    // xdpilone crate author didn't bother to 
    // implement std::error::Error for Errno,
    // so we have to catch it manually
    let mut umem: Umem = {
        unsafe { Umem::new(config, ptr).expect("umem creation error") }
    };


    let mut iface = IfInfo::invalid();
    iface.from_name(CString::new(args.iface.clone()).unwrap().as_c_str())
        .expect("couldn't find interface");
    let sock = Socket::with_shared(&iface, &umem)
        .expect("couldn't create xsk");
    let mut fq_cq = umem.fq_cq(&sock)
        .expect("couldn't map fill and completion queues"); // Fill Queue / Completion Queue

    let cfg = SocketConfig {
        rx_size: None,
        tx_size: NonZeroU32::new(1 << 10),
        bind_flags: SocketConfig::XDP_BIND_ZEROCOPY | SocketConfig::XDP_BIND_NEED_WAKEUP,
    };
    let rxtx = umem.rx_tx(&sock, &cfg)
        .expect("couldn't map rx and tx queues"); // RX + TX Queues
    let mut tx = rxtx.map_tx()
        .expect("couldn't map tx queue");
    
    umem.bind(&rxtx)
        .expect("couldn't bind xsk");

    // THIS CONCLUDES THE SETUP (almost)


    let h = thread::spawn(move || {
        for _ in 0..100 {
            loop {
                match responses.pop(0) {
                    Ok(res) => {
                        println!("SYN-ACK FROM {}:{}", res.0.0, u16::from_be(res.0.1)); 
                        break;
                    }, 
                    _ => {},
                };
            } 
        }
    });


    prepare_buffers(&mut umem, 10, &args.iface);
    send(&mut umem, tx, fq_cq, &mut args.lhosts);

    // println!("{:?}", args.lhosts.list);

    h.join();

    Ok(())
}

#[derive(Copy, Clone)]
struct IpPort((u32, u16)); // sucks that i have to do this...
unsafe impl Pod for IpPort {} // clearly, it is safe to transmute this from bytes

#[inline(always)]
fn prepare_buffers(umem: &mut Umem, len: u32, interface: &str) {
    let iface = netdev::get_interfaces().into_iter()
        .find(|i| {i.name == interface}).unwrap();
    let gateway = iface.gateway.unwrap();

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
            fr[26..30].copy_from_slice(&iface.ipv4.get(0).unwrap().addr.octets());
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
        // TBD
        // dst tcp port
        fr[36..38].copy_from_slice(&port.to_be_bytes()); // to_bytes, or to_be_bytes, that is the question...
        // tcp checksum
        // TBD
    }
}

#[inline(always)]
fn send(umem: &mut Umem, mut tx: RingTx, mut fq_cq: DeviceQueue, hosts: &mut Hosts) {
    let mut buffers: Vec<u64> = (0..10).map(|idx| umem.frame(BufIdx(idx)).unwrap().addr.as_ptr() as *const u8 as u64).collect();
    let mut host_iter = hosts.rand_iter();

    'm: loop {
        while let Some(offset) = buffers.pop() { // enqueue tx
            if let Some(host) = host_iter.next() {
                finalize_buffer(offset, host);
                // let tx_frame = umem.frame(BufIdx(idx)).unwrap();
                {
                    let mut writer = tx.transmit(1);
                    writer.insert_once(XdpDesc { 
                        addr: offset,
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
            while let Some(offset) = reader.read() {
                buffers.push(offset);
            }
            reader.release();
        }
    }
    
    // for host in hosts.rand_iter() {
    //     if let Some(idx) = buffers.pop() { // enqueue transmissions
           
    //         finalize_buffer(&mut Umem, idk, host);
    //                 } else { // dequeue completions
    //         let mut reader = device.complete(1);
    //         loop { // we will block here just in case
    //             reader.read();
    //         }
    //     }
    // }
}

static SYN_PACKET: [u8; 54] = [
    // ETHER
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // (dst mac) : [0..6]
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // (src mac) : [6..12]
    0x08, 0x00, // proto
    
    // IP : [14..34]
    0x45, 0x00, 0x00, 0x28, // version etc 
    0x00, 0x01, 0x00, 0x00, // more irrelevant stuff
    0xff, 0x06, // ttl, protocol
    0x00, 0x00, // [checksum] : [24..26]
    0, 0, 0, 0, // (src ip) : [26..30]
    0, 0, 0, 0, // [dst ip] : [30..34]

    // TCP [34..54]
    0x05, 0x39, // source port known statically as 1337 (this is required for the ebpf program to know which packets are directed to the scanner)
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
            list: list,
        })
    }
}
