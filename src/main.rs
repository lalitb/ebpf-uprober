use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::UprobeOpts;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Command;

use signal_hook::consts::SIGINT;
use signal_hook::flag;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/uprober.skel.rs"));

fn main() {
    std::env::set_var("LIBBPF_DEBUG", "1");

    let skel_builder = UproberSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();

    println!("Opening skeleton...");
    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open skeleton");

    println!("Loading skeleton...");
    let skel = open_skel.load().expect("Failed to load skeleton");

    let bash_path = Path::new("/bin/bash");

    let uprobe = skel.progs.uprobe_readline;

    // Print program info
    println!("Program name: {:?}", uprobe.name());
    println!("Program type: {:?}", uprobe.prog_type());

    let opts = UprobeOpts {
        func_name: "readline".into(), // Function name inside the binary
        retprobe: false,              // false for entry, true for return probes
        ref_ctr_offset: 0,
        cookie: 0,
        _non_exhaustive: (),
    };

    // Attach the uprobe using the binary's file descriptor
    println!("Attaching uprobe...");
    let _ = uprobe
        .attach_uprobe_with_opts(-1, bash_path, 0, opts) // 0 is the function offset
        .expect("Failed to attach uprobe");

    println!("Uprobe attached! Now start /bin/bash and type a command.");
    /*loop {
        Command::new("bpftool")
            .arg("prog")
            .arg("tracelog")
            .status()
            .expect("Failed to read BPF logs");
    }*/
    // Open the trace_pipe file
    /*let file =
        File::open("/sys/kernel/debug/tracing/trace_pipe").expect("Failed to open trace_pipe");
    let reader = BufReader::new(file);

    // Read and print each line from trace_pipe
    for line in reader.lines() {
        match line {
            Ok(log) => println!("{}", log),
            Err(e) => eprintln!("Error reading line: {}", e),
        }
    }*/
    // Set up a flag to handle SIGINT (Ctrl+C) for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    flag::register(SIGINT, r).expect("Failed to set up signal handler");

    // Keep the program running until SIGINT is received
    while running.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
    }

    println!("Exiting...");
}
