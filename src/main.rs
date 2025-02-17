use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::UprobeOpts;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Command;

include!(concat!(env!("OUT_DIR"), "/uprober.skel.rs"));

fn main() {
    let skel_builder = UproberSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();

    let open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open skeleton");

    let skel = open_skel.load().expect("Failed to load skeleton");

    let bash_path = Path::new("/bin/bash");

    let uprobe = skel.progs.uprobe_readline;

    let opts = UprobeOpts {
        func_name: "readline".into(), // Function name inside the binary
        retprobe: false,              // false for entry, true for return probes
        ref_ctr_offset: 0,
        cookie: 0,
        _non_exhaustive: (),
    };

    // Attach the uprobe using the binary's file descriptor
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
    let file =
        File::open("/sys/kernel/debug/tracing/trace_pipe").expect("Failed to open trace_pipe");
    let reader = BufReader::new(file);

    // Read and print each line from trace_pipe
    for line in reader.lines() {
        match line {
            Ok(log) => println!("{}", log),
            Err(e) => eprintln!("Error reading line: {}", e),
        }
    }
}
