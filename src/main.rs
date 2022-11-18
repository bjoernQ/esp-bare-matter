#![no_std]
#![no_main]

use core::cell::RefCell;

use bare_matter::interaction_model::InvokeHandlerResponse;
use bare_matter::{
    create_on_off_endpoint, create_root_device, Certificates, MatterContext, MatterServer,
};
use critical_section::Mutex;
use embedded_svc::ipv4::Interface;
use embedded_svc::wifi::ClientConfiguration;
use embedded_svc::wifi::{Configuration, Wifi};
use esp32c3_hal::gpio::{Output, PushPull};
use esp32c3_hal::{
    clock::{ClockControl, CpuClock},
    pac::Peripherals,
    prelude::*,
    timer::TimerGroup,
    Rtc,
};
use esp32c3_hal::{Rng, IO};
use esp_backtrace as _;
use esp_println::println;
use esp_wifi::current_millis;
use esp_wifi::wifi_interface::{Network, UdpSocket};
use esp_wifi::{
    create_network_stack_storage, network_stack_storage, wifi::utils::create_network_interface,
};
use getrandom::register_custom_getrandom;
use riscv_rt::entry;
use smoltcp::socket::UdpPacketMetadata;
use smoltcp::wire::Ipv4Address;

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

// From Chip-Test-DAC-FFF1-8000-0007-Key.der
const DEVICE_PRIVATE_KEY: [u8; 32] =
    hex_literal::hex!("727F1005CBA47ED7822A9D930943621617CFD3B79D9AF528B801ECF9F1992204");

// From Chip-Test-DAC-FFF1-8000-0007-Cert.der
const DEVICE_CERTIFICATE: [u8;492] = hex_literal::hex!("308201e83082018fa0030201020208143c9d1689f498f0300a06082a8648ce3d04030230463118301606035504030c0f4d617474657220546573742050414931143012060a2b0601040182a27c02010c044646463131143012060a2b0601040182a27c02020c04383030303020170d3231303632383134323334335a180f39393939313233313233353935395a304b311d301b06035504030c144d6174746572205465737420444143203030303731143012060a2b0601040182a27c02010c044646463131143012060a2b0601040182a27c02020c04383030303059301306072a8648ce3d020106082a8648ce3d0301070342000462e2b6e1baff8d74a6fd8216c4cb67a3363a31e691492792e61aee610261481396725ef95e142686ba98f339b0ff65bc338bec7b9e8be0bdf3b2774982476220a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414ee95ad96983a9ea95bcd2b00dc5e671727690383301f0603551d23041830168014af42b7094debd515ec6ecf33b81115225f325288300a06082a8648ce3d040302034700304402202f51cf53bf7777df7318094b9db595eebf2fa881c8c572847b1e689ece654264022029782708ee6b32c7f08ff63dbe618e9a580bb14c183bc288777adf9e2dcff5e6");

// From Chip-Test-PAI-FFF1-8000-Cert.der
const PRODUCT_INTERMEDIATE_CERTIFICATE: [u8;472] = hex_literal::hex!("308201d43082017aa00302010202083e6ce6509ad840cd300a06082a8648ce3d04030230303118301606035504030c0f4d617474657220546573742050414131143012060a2b0601040182a27c02010c04464646313020170d3231303632383134323334335a180f39393939313233313233353935395a30463118301606035504030c0f4d617474657220546573742050414931143012060a2b0601040182a27c02010c044646463131143012060a2b0601040182a27c02020c04383030303059301306072a8648ce3d020106082a8648ce3d0301070342000480ddf11b228f3e31f63bcf5798da14623aebbde82ef378eeadbfb18fe1abce31d08ed4b20604b6ccc6d9b5fab64e7de10cb74be017c9ec1516056d70f2cd0b22a366306430120603551d130101ff040830060101ff020100300e0603551d0f0101ff040403020106301d0603551d0e04160414af42b7094debd515ec6ecf33b81115225f325288301f0603551d230418301680146afd22771f511fecbf1641976710dcdc31a1717e300a06082a8648ce3d040302034800304502210096c9c8cf2e01886005d8f5bc72c07b75fd9a57695ac4911131138bea033ce50302202554943be57d53d6c475f7d23ebfcfc2036cd29ba6393ec7efad8714ab718219");

// From DeviceAttestationCredsExample.cpp
const CERTIFICATE_DECLARATION: [u8;541] = hex_literal::hex!("3082021906092a864886f70d010702a082020a30820206020103310d300b06096086480165030402013082017106092a864886f70d010701a08201620482015e152400012501f1ff3602050080050180050280050380050480050580050680050780050880050980050a80050b80050c80050d80050e80050f80051080051180051280051380051480051580051680051780051880051980051a80051b80051c80051d80051e80051f80052080052180052280052380052480052580052680052780052880052980052a80052b80052c80052d80052e80052f80053080053180053280053380053480053580053680053780053880053980053a80053b80053c80053d80053e80053f80054080054180054280054380054480054580054680054780054880054980054a80054b80054c80054d80054e80054f80055080055180055280055380055480055580055680055780055880055980055a80055b80055c80055d80055e80055f80056080056180056280056380182403162c04135a494732303134325a423333303030332d32342405002406002507942624080018317d307b020103801462fa823359acfaa9963e1cfa140addf504f37160300b0609608648016503040201300a06082a8648ce3d04030204473045022024e5d1f47a7d7b0d206a26ef699b7c9757b72d469089de3192e678c745e7f60c022100f8aa2fa711fcb79b97e397ceda667bae464e2bd3ffdfc3cced7aa8ca5f4c1a7c");

register_custom_getrandom!(custom_getrandom);

static LED: Mutex<RefCell<Option<esp32c3_hal::gpio::Gpio5<Output<PushPull>>>>> =
    Mutex::new(RefCell::new(None));

#[entry]
fn main() -> ! {
    esp_println::logger::init_logger(log::LevelFilter::Info);
    esp_wifi::init_heap();

    let peripherals = Peripherals::take().unwrap();
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock160MHz).freeze();

    // Disable the RTC and TIMG watchdog timers
    let mut rtc = Rtc::new(peripherals.RTC_CNTL);
    let timer_group0 = TimerGroup::new(peripherals.TIMG0, &clocks);
    let mut wdt0 = timer_group0.wdt;
    let timer_group1 = TimerGroup::new(peripherals.TIMG1, &clocks);
    let mut wdt1 = timer_group1.wdt;

    rtc.swd.disable();
    rtc.rwdt.disable();
    wdt0.disable();
    wdt1.disable();

    let io = IO::new(peripherals.GPIO, peripherals.IO_MUX);
    let led = io.pins.gpio5.into_push_pull_output();
    critical_section::with(|cs| LED.borrow_ref_mut(cs).replace(led));

    let mut storage = create_network_stack_storage!(3, 8, 1, 1);
    let ethernet = create_network_interface(network_stack_storage!(storage));
    let mut wifi_interface = esp_wifi::wifi_interface::Wifi::new(ethernet);

    use esp32c3_hal::systimer::SystemTimer;
    let syst = SystemTimer::new(peripherals.SYSTIMER);
    esp_wifi::initialize(syst.alarm0, Rng::new(peripherals.RNG), &clocks).unwrap();

    let client_config = Configuration::Client(ClientConfiguration {
        ssid: SSID.into(),
        password: PASSWORD.into(),
        ..Default::default()
    });
    let res = wifi_interface.set_configuration(&client_config);
    println!("set_configuration returned {:?}", res);
    let res = wifi_interface.connect();
    println!("wifi_connect returned {:?}", res);

    // wait to get connected
    loop {
        if let Ok(true) = wifi_interface.is_connected() {
            break;
        }
    }

    let network = Network::new(wifi_interface, current_millis);

    let mut local_ip = [0u8; 4];
    // wait to get connected and have an ip
    loop {
        network.poll_dhcp().unwrap();
        network.work();

        if network.is_iface_up() {
            println!("got ip {:?}", network.get_ip_info());
            local_ip.copy_from_slice(&network.get_ip_info().unwrap().ip.octets());
            break;
        }
    }

    println!("Use Android CHIPTOOL app, select PROVISION CHIP DEVICE WITH WI-FI, INPUT DEVICE ADDRESS, enter {}.{}.{}.{} and tap on COMMISSION",
        local_ip[0],
        local_ip[1],
        local_ip[2],
        local_ip[3],
    );
    println!("If successful you can toggle GPIO 5 via LIGHT ON/OFF & LEVEL CLUSTER");

    let mut rx_meta1 = [UdpPacketMetadata::EMPTY; 4];
    let mut rx_buffer1 = [0u8; 1536];
    let mut tx_meta1 = [UdpPacketMetadata::EMPTY; 4];
    let mut tx_buffer1 = [0u8; 1536];
    let udp_socket1 = network.get_udp_socket(
        &mut rx_meta1,
        &mut rx_buffer1,
        &mut tx_meta1,
        &mut tx_buffer1,
    );

    let mut rx_meta2 = [UdpPacketMetadata::EMPTY; 4];
    let mut rx_buffer2 = [0u8; 1536];
    let mut tx_meta2 = [UdpPacketMetadata::EMPTY; 4];
    let mut tx_buffer2 = [0u8; 1536];
    let udp_socket2 = network.get_udp_socket(
        &mut rx_meta2,
        &mut rx_buffer2,
        &mut tx_meta2,
        &mut tx_buffer2,
    );

    // matter stuff
    let certificates = Certificates {
        device_private_key: DEVICE_PRIVATE_KEY,
        device_certificate: heapless::Vec::from_slice(&DEVICE_CERTIFICATE).unwrap(),
        product_intermediate_certificate: heapless::Vec::from_slice(
            &PRODUCT_INTERMEDIATE_CERTIFICATE,
        )
        .unwrap(),
        certificate_declaration: heapless::Vec::from_slice(&CERTIFICATE_DECLARATION).unwrap(),
    };

    let context = MatterContext::new(certificates);

    let on_handler = |v, _s: &MatterContext| {
        println!("\n\non_handler {:?}\n\n", v);
        critical_section::with(|cs| {
            let mut led = LED.borrow_ref_mut(cs);
            let led = led.as_mut().unwrap();

            led.set_high().unwrap();
        });

        InvokeHandlerResponse::Result(0)
    };
    let off_handler = |v, _s: &MatterContext| {
        println!("\n\noff_handler {:?}\n\n", v);
        critical_section::with(|cs| {
            let mut led = LED.borrow_ref_mut(cs);
            let led = led.as_mut().unwrap();

            led.set_low().unwrap();
        });

        InvokeHandlerResponse::Result(0)
    };
    let toggle_handler = |v, _ctx: &MatterContext| {
        println!("\n\ntoggle_handler {:?}\n\n", v);
        critical_section::with(|cs| {
            let mut led = LED.borrow_ref_mut(cs);
            let led = led.as_mut().unwrap();

            led.toggle().unwrap();
        });

        InvokeHandlerResponse::Result(0)
    };

    let endpoints = &[
        create_root_device!(),
        create_on_off_endpoint!(on_handler, off_handler, toggle_handler),
    ];

    let mut device = bare_matter::interaction_model::Device::new(endpoints);

    let mut rng = EspRng::new();
    let mut matter_socket = EspUdpSocket::new(udp_socket1);
    let mut matter_multicast_socket = EspUdpMulticastSocket::new(udp_socket2);
    let mut server = MatterServer::new(
        &mut matter_socket,
        &mut matter_multicast_socket,
        local_ip,
        &mut rng,
        &mut device,
        &context,
    );

    loop {
        server.poll(current_millis());
    }
}

struct EspUdpSocket<'a> {
    socket: UdpSocket<'a, 'a>,
}

impl<'a> EspUdpSocket<'a> {
    pub fn new(socket: UdpSocket<'a, 'a>) -> Self {
        Self { socket }
    }
}

impl<'a> bare_matter::UdpSocket for EspUdpSocket<'a> {
    fn send(
        &mut self,
        addr: [u8; 4],
        port: u16,
        buffer: heapless::Vec<u8, 1024>,
    ) -> Result<(), ()> {
        let res = self.socket.send(
            Ipv4Address::new(addr[0], addr[1], addr[2], addr[3]),
            port,
            &buffer,
        );
        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn receive(&mut self) -> Result<(heapless::Vec<u8, 1024>, [u8; 4], u16), ()> {
        let mut buffer = [0u8; 1024];
        let res = self.socket.receive(&mut buffer);
        match res {
            Ok((len, sender, port)) => Ok((
                heapless::Vec::from_slice(&buffer[..len]).unwrap(),
                sender,
                port,
            )),
            Err(_) => Err(()),
        }
    }

    fn bind(&mut self, port: u16) -> Result<(), ()> {
        let res = self.socket.bind(port);
        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

struct EspUdpMulticastSocket<'a> {
    socket: UdpSocket<'a, 'a>,
}

impl<'a> EspUdpMulticastSocket<'a> {
    pub fn new(socket: UdpSocket<'a, 'a>) -> Self {
        Self { socket }
    }
}

impl<'a> bare_matter::UdpMulticastSocket for EspUdpMulticastSocket<'a> {
    fn send(
        &mut self,
        addr: [u8; 4],
        port: u16,
        buffer: heapless::Vec<u8, 2048>,
    ) -> Result<(), ()> {
        let res = self.socket.send(
            Ipv4Address::new(addr[0], addr[1], addr[2], addr[3]),
            port,
            &buffer,
        );
        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn receive(&mut self) -> Result<(heapless::Vec<u8, 2048>, [u8; 4], u16), ()> {
        let mut buffer = [0u8; 2048];
        let res = self.socket.receive(&mut buffer);
        match res {
            Ok((len, sender, port)) => Ok((
                heapless::Vec::from_slice(&buffer[..len]).unwrap(),
                sender,
                port,
            )),
            Err(_) => Err(()),
        }
    }

    fn bind(&mut self, multiaddr: &[u8; 4], port: u16) -> Result<(), ()> {
        let _res = self.socket.join_multicast_group(Ipv4Address::new(
            multiaddr[0],
            multiaddr[1],
            multiaddr[2],
            multiaddr[3],
        ));

        let res = self.socket.bind(port);
        match res {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}

struct EspRng {}

impl EspRng {
    pub fn new() -> Self {
        Self {}
    }
}

impl rand_core::CryptoRng for EspRng {}

impl rand_core::RngCore for EspRng {
    fn next_u32(&mut self) -> u32 {
        // todo!()
        42
    }

    fn next_u64(&mut self) -> u64 {
        // todo!()
        42u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        //todo!()
        let not_random = [1, 54, 223, 42, 23, 3, 70, 33, 23, 177, 32, 39];
        let mut idx = 0;
        for b in dest {
            *b = not_random[idx];
            idx += 1;
            if idx >= not_random.len() {
                idx = 0;
            }
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        //todo!()
        self.fill_bytes(dest);
        Ok(())
    }
}

pub fn custom_getrandom(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let not_random = [1, 54, 99, 223, 42, 23, 3, 70, 33, 23, 177, 255, 32, 39];
    let mut idx = 0;
    for b in buf {
        *b = not_random[idx];
        idx += 1;
        if idx >= not_random.len() {
            idx = 0;
        }
    }

    Ok(())
}

pub fn wait_ms(ms: u32) {
    let started = esp_wifi::current_millis() as u32;
    while (esp_wifi::current_millis() as u32) < started + ms {
        // nothing
    }
}
