mod config;

use std::net::Ipv4Addr;
use std::mem::size_of;
use std::os::unix::io::RawFd;
use libc::{
    AF_INET, SOCK_RAW, IPPROTO_IP, IPPROTO_IPIP,
    socket, recvfrom, sendto, setsockopt,
    in_addr, sockaddr_in, socklen_t, c_void
};
use once_cell::sync::OnceCell;

use crate::config::*;

static MTU: OnceCell<usize> = OnceCell::new();

const BUFSZ: usize = 65536;

const IP_OFFSET_VER_LEN:   usize = 0;
const IP_OFFSET_TOS:       usize = 1;
const IP_OFFSET_LENGTH:    usize = 2;
const IP_OFFSET_ID:        usize = 4;
const IP_OFFSET_FLAG:      usize = 6;
const IP_OFFSET_TTL:       usize = 8;
const IP_OFFSET_PROTOCOL:  usize = 9;
const IP_OFFSET_CKSUM:     usize = 10;
const IP_OFFSET_SRC_IP:    usize = 12;
const IP_OFFSET_DST_IP:    usize = 16;
const IP_HDR_SZ:           usize = 20; 

fn calculate_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
	let mut i = 0;
	let len = header.len();

	while i < len - 1 {
        let word = (header[i] as u16) << 8 | (header[i + 1] as u16);
        sum += word as u32;
        i += 2;
    }

    if len % 2 == 1 {
        sum += (header[len - 1] as u32) << 8;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn fragmentation(fd: RawFd, packet:&[u8], dst_ip:Ipv4Addr) {
    let ip_hdr = &packet[0..IP_HDR_SZ];
    let payload = &packet[IP_HDR_SZ..];
    let tlen = packet.len();
    let mtu = *MTU.get().unwrap();

    let fragment_size = ((mtu - IP_HDR_SZ) / 8) * 8;
    let num_fragments = (tlen - IP_HDR_SZ + fragment_size - 1) / fragment_size;  

    for i in 0..num_fragments {
        let mut fragment_packet = Vec::new();

        let offset = i * fragment_size;
        let more_fragments = (i + 1) < num_fragments; // Is this the last?
        let mut fragment_header = ip_hdr.to_vec();


        let frag_len = if more_fragments {
            fragment_size + IP_HDR_SZ
        }
        else {
            tlen - offset + IP_HDR_SZ //TODO: Should I include the IP Header Size?
        };

        // Set Length
        fragment_header[IP_OFFSET_LENGTH] = (frag_len >> 8) as u8;
        fragment_header[IP_OFFSET_LENGTH + 1] = (frag_len & 0xFF) as u8;

        // Set Fragment Offset and MF flag
        let mut flags_offset = offset << 3;
        if more_fragments {
            flags_offset |= 0x2000; // MF flag
        }

        // Set Length
        fragment_header[IP_OFFSET_FLAG] = (frag_len >> 8) as u8;
        fragment_header[IP_OFFSET_FLAG + 1] = (frag_len & 0xFF) as u8;

        //Reset Checksum
        fragment_header[IP_OFFSET_CKSUM] = 0;
        fragment_header[IP_OFFSET_CKSUM + 1] = 0;

        //Recalculate Checksum
        let checksum = calculate_checksum(&fragment_header);
        fragment_header[IP_OFFSET_CKSUM] = (checksum >> 8) as u8;
        fragment_header[IP_OFFSET_CKSUM + 1] = (checksum & 0xFF) as u8;

        // Create fragment packet
        fragment_packet.extend_from_slice(&fragment_header); // Add IP header for the fragment
        fragment_packet.extend_from_slice(&payload[offset..(i + 1) * fragment_size]); // Add body for the fragment
        
        send_packet(fd, &fragment_packet, dst_ip);
    }
}


fn encapsulate_packet(send_sock:RawFd, buf: &[u8], recv_len: isize, new_dst: Ipv4Addr) -> Vec<u8> {
    let mtu = *MTU.get().unwrap();
    let mut new_buf = Vec::new();

    //Copy the original IP header
    let original_ip_header = &buf[0..IP_HDR_SZ];

    let mut new_hdr = [0u8; IP_HDR_SZ];

    new_hdr.copy_from_slice(original_ip_header);
    let tlen:usize = recv_len as usize + IP_HDR_SZ;

    // Update the Total Length
    new_hdr[IP_OFFSET_LENGTH] = (tlen >> 8) as u8;
    new_hdr[IP_OFFSET_LENGTH + 1] = (tlen & 0xFF) as u8;

    // Update the Protocol Type
    new_hdr[IP_OFFSET_PROTOCOL] = IPPROTO_IPIP as u8;

    // Copy the new Destination IP address
    new_hdr[IP_OFFSET_DST_IP..IP_OFFSET_DST_IP + 4].copy_from_slice(&new_dst.octets());

    // Initialize checksum field
    new_hdr[IP_OFFSET_CKSUM] = 0;
    new_hdr[IP_OFFSET_CKSUM + 1] = 0;

    let checksum = calculate_checksum(&new_hdr);
    // Initialize checksum field
    new_hdr[IP_OFFSET_CKSUM] = (checksum >> 8) as u8;
    new_hdr[IP_OFFSET_CKSUM + 1] = (checksum & 0xFF) as u8;

    // Encapsulated 패킷 구성
    new_buf.extend_from_slice(&new_hdr);
    new_buf.extend_from_slice(&buf[..recv_len as usize]);

    //DF flag check
    let df_flag = (buf[IP_OFFSET_FLAG] & 0x40) != 0;
    if !df_flag && new_buf.len() > mtu {
        fragmentation(send_sock, &new_buf, new_dst);
        return Vec::new();
    }

    new_buf
}


fn decapsulate_packet(buf: &[u8], recv_len: isize) -> Vec<u8> {
    // The IP header for decapsulation is already in the buffer,
    // we need to remove the outer IP header (20 bytes)
    let mut decapsulated_buf = Vec::new();
    decapsulated_buf.extend_from_slice(&buf[IP_HDR_SZ..recv_len as usize]);
    decapsulated_buf
}


fn send_packet(fd: RawFd, buf: &[u8], dst_ip: Ipv4Addr) {

    let dest_addr  = sockaddr_in {
        sin_family: AF_INET as u8,
        sin_len: 0,
        sin_port: 0,
        sin_addr: in_addr {
			s_addr: u32::from(dst_ip)
		},
        sin_zero: [0; 8],
    };


    unsafe {
        let send_result: isize = sendto(
            fd,
            buf.as_ptr() as *const c_void,
            buf.len(),
            0,
            &dest_addr as *const _ as *const _,
            std::mem::size_of::<sockaddr_in>() as socklen_t,
        );

        if send_result < 0 {
            println!("Failed to send packet");
        } else {
            println!("Packet sent successfully!");
        }
    }
}


fn main() {
    if let Err(v) = read_conf("src/config/config"){
        println!("Failed Open file {}", v);
        return;
    }

    let config = CONFIG.get().expect("Failed to get config");
    let target = config.get("Target_Addr").unwrap();
    // let new_dst:Vec<u8> = config.get("New_Target_Addr").unwrap().split(".")
    //     .filter_map(|x|x.parse::<u8>().ok())
    //     .collect();
    let new_dst:Ipv4Addr = config.get("New_Target_Addr").unwrap().parse().unwrap();
    let mtu = config.get("MTU").unwrap().parse::<usize>().unwrap();
    MTU.set(mtu).expect("MTU Set failed");
    // println!("MTU: {}", MTU.get().unwrap());

    unsafe {
        let fd = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if fd < 0 {
            panic!("socket() failed");
        }

        let mut option = 1;
        if setsockopt(fd, libc::IPPROTO_IP, libc::IP_HDRINCL, &option as *const _ as *const c_void, std::mem::size_of_val(&option) as socklen_t) < 0 {
            panic!("Failed to set IP_HDRINCL option");
        }

        let send_sock: RawFd = socket(AF_INET, SOCK_RAW, IPPROTO_IPIP);
        if send_sock < 0 {
            panic!("Failed to create send socket");
        }

        let mut buf = [0u8; BUFSZ];

        loop {

            let mut src_addr = sockaddr_in {
                sin_family: AF_INET as u8,
                sin_len: 0,
                sin_port: 0,
                sin_addr: in_addr { s_addr: 0},
                sin_zero: [0; 8],
            };
            let mut addr_len = size_of::<sockaddr_in>() as socklen_t;

            //Receive packet
            let recv_len: isize = recvfrom(
                fd,
                buf.as_mut_ptr() as *mut _,
                BUFSZ,
                0,
                &mut src_addr as *mut _ as *mut _,
                &mut addr_len,
            );

            if recv_len < 0 {
                eprintln!("recvfrom() failed: {}", std::io::Error::last_os_error());
                continue; // Countinue to loop although error occurs.
            }

            // Extract Destination IP address
            let dst_ip = Ipv4Addr::new(
                buf[IP_OFFSET_DST_IP],
                buf[IP_OFFSET_DST_IP+1],
                buf[IP_OFFSET_DST_IP+2],
                buf[IP_OFFSET_DST_IP+3],
            );

            let src_ip = Ipv4Addr::new(
                buf[IP_OFFSET_SRC_IP],
                buf[IP_OFFSET_SRC_IP + 1],
                buf[IP_OFFSET_SRC_IP + 2],
                buf[IP_OFFSET_SRC_IP + 3],
            );

            if dst_ip.to_string() == *target {
                println!("Encapsulation packet");
                let new_buf = encapsulate_packet(send_sock, &buf, recv_len, new_dst);

                // Send the encapsulated packet
                send_packet(send_sock, &new_buf, dst_ip);
                println!("Decapsulated packet sent successfully!");
            }
            else if src_ip.to_string() == *target {

                println!("Decapsulating packet...");
                let decapsulated_buf = decapsulate_packet(&buf, recv_len);

                // Send the decapsulated packet
                send_packet(send_sock, &decapsulated_buf, dst_ip);
                println!("Decapsulated packet sent successfully!");
            }
        }
    }
}
