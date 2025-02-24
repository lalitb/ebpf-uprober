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
    println!(
        "Getting offset for symbol: {:?} inside {:?}",
        symbol_name,
        binary_path.display()
    );
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
    let mut links = Vec::new();
    // Enable verbose logging
    std::env::set_var("LIBBPF_DEBUG", "1");

    let test_program_path = Path::new("/tmp/test_program");
    /*// Get the actual offset of test_function
    let test_function_offset = get_symbol_offset(test_program_path, "test_function")
        .expect("Failed to find test_function symbol offset");

    println!(
        "Found test_function at offset: 0x{:x}",
        test_function_offset
    );*/

    let skel_builder = UproberSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();

    println!("Opening skeleton...");
    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open skeleton");

    println!("Loading skeleton...");
    let skel = open_skel.load().expect("Failed to load skeleton");

    let uprobe = skel.progs.uprobe_test_function;

    // Print program info for debugging
    println!("Program name: {:?}", uprobe.name());
    println!("Program type: {:?}", uprobe.prog_type());

    let opts = UprobeOpts {
        func_name: "test_function".into(),
        retprobe: false,
        ref_ctr_offset: 0,
        cookie: 0,
        _non_exhaustive: (),
    };
    let test_function_offset = 0; // This is the offset from the start of function.
    println!("Attaching uprobe at offset 0x{:x}...", test_function_offset);
    let uprobe_link = uprobe
        .attach_uprobe_with_opts(-1, test_program_path, test_function_offset, opts)
        .expect("Failed to attach uprobe");
    links.push(uprobe_link);

    println!("Loading skeleton...");

    let uretprobe = skel.progs.uretprobe_test_function;
    // Attach uretprobe (return probe)
    let retprobe_opts = UprobeOpts {
        func_name: "test_function".into(),
        retprobe: true, // Return probe
        ref_ctr_offset: 0,
        cookie: 0,
        _non_exhaustive: (),
    };

    println!(
        "Attaching uretprobe at offset 0x{:x}...",
        test_function_offset
    );
    let uretprobe_link = uretprobe
        .attach_uprobe_with_opts(-1, test_program_path, test_function_offset, retprobe_opts)
        .expect("Failed to attach return uretprobe");
    links.push(uretprobe_link);

    println!("Uprobe attached successfully!");

    // Keep the program running
    println!("Press Ctrl+C to exit...");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
