use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::UprobeOpts;
use std::fs::File;
use std::path::Path;
use std::process::Command;
use libbpf_rs::skel::OpenSkel;
use std::os::fd::AsRawFd;
use std::mem::MaybeUninit;

include!(concat!(env!("OUT_DIR"), "/uprober.skel.rs"));

fn main() {
    let skel_builder = UproberSkelBuilder::default();
    let mut open_obj = MaybeUninit::uninit();

    let mut open_skel = skel_builder
        .open(&mut open_obj)
        .expect("Failed to open skeleton");


    let mut skel = open_skel.load().expect("Failed to load skeleton");

    let bash_path = Path::new("/bin/bash");
    // Open the binary to get a file descriptor
    let file = File::open(bash_path).expect("Failed to open binary");
    let binary_fd = file.as_raw_fd(); // Get the raw file descriptor

    let uprobe = skel.progs().uprobe_readline();

    let opts = UprobeOpts {
        func_name: "readline".into(), // Function name inside the binary
        retprobe: false,              // false for entry, true for return probes
        ref_ctr_offset: 0,
        cookie: 0,
        _non_exhaustive: (),
    };

    // Attach the uprobe using the binary's file descriptor
    uprobe
        .attach_uprobe_opts(binary_fd, 0, opts) // 0 is the function offset
        .expect("Failed to attach uprobe");

    println!("Uprobe attached! Now start /bin/bash and type a command.");
    loop {
        Command::new("bpftool")
            .arg("prog")
            .arg("tracelog")
            .status()
            .expect("Failed to read BPF logs");
    }
}
