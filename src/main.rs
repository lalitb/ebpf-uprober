use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::UprobeOpts;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Command;

include!(concat!(env!("OUT_DIR"), "/uprober.skel.rs"));

fn get_symbol_offset(binary_path: &Path, symbol_name: &str) -> Option<usize> {
    let output = Command::new("nm")
        .arg("-D")
        .arg(binary_path)
        .output()
        .ok()?;

    let output_str = String::from_utf8_lossy(&output.stdout);
    for line in output_str.lines() {
        if line.contains(symbol_name) {
            // Parse the hex offset from the nm output
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                return u64::from_str_radix(parts[0], 16).ok().map(|x| x as usize);
            }
        }
    }
    None
}

fn main() {
    // Enable verbose logging
    std::env::set_var("LIBBPF_DEBUG", "1");

    let bash_path = Path::new("/bin/bash");

    // Get the actual offset of readline
    //let readline_offset =
    //    get_symbol_offset(bash_path, "readline").expect("Failed to find readline symbol offset");

    let readline_offset: usize = 0;

    println!("Found readline at offset: 0x{:x}", readline_offset);

    let skel_builder = UproberSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();

    println!("Opening skeleton...");
    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open skeleton");

    println!("Loading skeleton...");
    let skel = open_skel.load().expect("Failed to load skeleton");

    let uprobe = skel.progs.uprobe_readline;

    // Print program info for debugging
    println!("Program name: {:?}", uprobe.name());
    println!("Program type: {:?}", uprobe.prog_type());

    let opts = UprobeOpts {
        func_name: "readline".into(),
        retprobe: false,
        ref_ctr_offset: 0,
        cookie: 0,
        _non_exhaustive: (),
    };

    println!("Attaching uprobe at offset 0x{:x}...", readline_offset);
    let _ = uprobe
        .attach_uprobe_with_opts(-1, bash_path, readline_offset, opts)
        .expect("Failed to attach uprobe");

    println!("Uprobe attached successfully!");

    // Try to verify the attachment
    if let Ok(output) = Command::new("cat")
        .arg("/sys/kernel/debug/tracing/uprobe_events")
        .output()
    {
        println!("Current uprobe events:");
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }

    // Read both trace and trace_pipe
    println!("Monitoring traces...");
    let trace_pipe = std::thread::spawn(|| {
        let files = vec![
            "/sys/kernel/debug/tracing/trace",
            "/sys/kernel/debug/tracing/trace_pipe",
        ];

        for file_path in files {
            if let Ok(file) = File::open(file_path) {
                println!("Reading from {}", file_path);
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    if let Ok(log) = line {
                        println!("[{}] {}", file_path, log);
                    }
                }
            }
        }
    });

    // Keep the program running
    println!("Press Ctrl+C to exit...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
