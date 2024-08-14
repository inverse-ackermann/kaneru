#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{xdp, map},
    programs::XdpContext,
    maps::Stack,
};

use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
};

#[map]
static mut RESPONSES: Stack<(u32, u16)> = Stack::with_max_entries(1 << 20, 0);

#[xdp]
pub fn receive(ctx: XdpContext) -> u32 {
    match try_receive(ctx) {
        Ok(ret) => ret,
        _ => xdp_action::XDP_PASS,
    }
}

const PORT: u16 = 1337u16.to_be();

fn try_receive(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *mut EthHdr = unsafe { ptr_at(&ctx, 0)? };
    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr: *mut Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };  
    if unsafe { *ip_hdr }.proto != IpProto::Tcp {
        return Ok(xdp_action::XDP_PASS)
    }

    let tcp_hdr: *mut TcpHdr = unsafe { 
        ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? 
    };

    match unsafe { (*tcp_hdr).dest } {
        PORT => {
            if unsafe { *tcp_hdr }.rst() != 0 { // RST bit is set, dropping the packet
                Ok(xdp_action::XDP_DROP)
            } else {
                unsafe { RESPONSES.push(&((*ip_hdr).src_addr, (*tcp_hdr).source), 0) }.map_err(|_| ())?;
                Ok(xdp_action::XDP_PASS)
                // // save the fact that we got a packet from the host

                // // modify the packet in place and resend it
                // unsafe { 
                //     // ethernet
                //     core::mem::swap(&mut (*eth_hdr).src_addr, &mut (*eth_hdr).dst_addr);

                //     // ip
                //     core::mem::swap(&mut (*ip_hdr).src_addr, &mut (*ip_hdr).dst_addr); 
                //     (*ip_hdr).ttl = 0xFF;
                //     // unimplemented!(); // checksum
                
                //     // tcp
                //     core::mem::swap(&mut (*tcp_hdr).source, &mut (*tcp_hdr).dest);
                //     // new_seq = ack
                //     // new_ack = seq + 1
                //     core::mem::swap(&mut (*tcp_hdr).seq, &mut (*tcp_hdr).ack_seq);
                //     (*tcp_hdr).ack_seq = (u32::from_be((*tcp_hdr).ack_seq) + 1).to_be();
                //     // unimplemented!(); // checksum
                //     (*tcp_hdr).set_syn(0);
                //     (*tcp_hdr).set_rst(1);
                // }

                // Ok(xdp_action::XDP_TX)
            }
        },
        _ => Ok(xdp_action::XDP_PASS),
    }
}



#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
