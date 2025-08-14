use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Medium, TunTapInterface};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Opening TAP interface...");
    
    let mut device = TunTapInterface::new("tap0", Medium::Ethernet)?;
    println!("✓ Opened tap0");

    let config = Config::new(HardwareAddress::Ethernet(EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])));
    let mut iface = Interface::new(config, &mut device, Instant::now());
    
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs.push(IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)).unwrap();
    });
    
    println!("✓ Connected! Test with: ping 192.168.69.1");
    
    let mut sockets = SocketSet::new(vec![]);
    
    loop {
    	let timestamp = Instant::now();
        let _ = iface.poll(timestamp, &mut device, &mut sockets);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

