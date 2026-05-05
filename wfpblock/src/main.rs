use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
use std::env;
use std::net::Ipv4Addr;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("usage: .\\wfpblock.exe <ip1> <ip2> <ip3> ...");
        println!("example: .\\wfpblock.exe 8.8.8.8 1.1.1.1 142.250.190.46");
        return Ok(());
    }

    let mut target_ips: Vec<u32> = Vec::new();
    for arg in &args[1..] {
        match arg.parse::<Ipv4Addr>() {
            Ok(addr) => target_ips.push(u32::from_be_bytes(addr.octets())),
            Err(_) => println!("[!] warning: '{}' is not a valid ipv4 address. skipping.", arg),
        }
    }

    if target_ips.is_empty() {
        println!("[!] no valid target ips provided. exiting.");
        return Ok(());
    }

    unsafe {
        let mut engine_handle: HANDLE = HANDLE(0);
        let status = wfp::FwpmEngineOpen0(None, 10, None, None, &mut engine_handle);
        if status != 0 { return Err(Error::from_win32()); }

        let target_port: u16 = 443; 
        let mut max_weight = u64::MAX;
        let mut filter_ids: Vec<u64> = Vec::new();

        println!("[+] targeting {} endpoints on port {}...", target_ips.len(), target_port);

        for &ip in &target_ips {
            let mut conditions = [
                wfp::FWPM_FILTER_CONDITION0 {
                    fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: wfp::FWP_MATCH_EQUAL,
                    conditionValue: wfp::FWP_CONDITION_VALUE0 {
                        r#type: wfp::FWP_UINT32,
                        Anonymous: wfp::FWP_CONDITION_VALUE0_0 { uint32: ip },
                    },
                },
                wfp::FWPM_FILTER_CONDITION0 {
                    fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_PORT,
                    matchType: wfp::FWP_MATCH_EQUAL,
                    conditionValue: wfp::FWP_CONDITION_VALUE0 {
                        r#type: wfp::FWP_UINT16,
                        Anonymous: wfp::FWP_CONDITION_VALUE0_0 { uint16: target_port },
                    },
                },
            ];

            let mut name_v: Vec<u16> = "wfpblock\0".encode_utf16().collect();
            let filter = wfp::FWPM_FILTER0 {
                displayData: wfp::FWPM_DISPLAY_DATA0 { 
                    name: PWSTR(name_v.as_mut_ptr()), 
                    ..Default::default() 
                },
                flags: wfp::FWPM_FILTER_FLAG_PERSISTENT,
                layerKey: wfp::FWPM_LAYER_OUTBOUND_TRANSPORT_V4, 
                action: wfp::FWPM_ACTION0 { 
                    r#type: wfp::FWP_ACTION_BLOCK, 
                    ..Default::default() 
                },
                filterCondition: conditions.as_mut_ptr(),
                numFilterConditions: 2,
                weight: wfp::FWP_VALUE0 { 
                    r#type: wfp::FWP_UINT64, 
                    Anonymous: wfp::FWP_VALUE0_0 { uint64: &mut max_weight } 
                },
                ..Default::default()
            };

            let mut filter_id: u64 = 0;
            let status = wfp::FwpmFilterAdd0(engine_handle, &filter, None, Some(&mut filter_id));

            if status == 0 {
                println!("[+] blocked: {} | id: {}", Ipv4Addr::from(ip.to_be_bytes()), filter_id);
                filter_ids.push(filter_id);
            } else {
                println!("[!] failed to block {}. error: 0x{:X}", Ipv4Addr::from(ip.to_be_bytes()), status);
            }
        }

        if !filter_ids.is_empty() {
            println!("\n[*] all targets silenced. Press enter to restore network and exit...");
            let mut input = String::new();
            let _ = std::io::stdin().read_line(&mut input);
           
            for id in filter_ids {
                let _ = wfp::FwpmFilterDeleteById0(engine_handle, id);
            }
            println!("[+] all filters removed. exiting...");
        }

        let _ = wfp::FwpmEngineClose0(engine_handle);
    }
    Ok(())
}