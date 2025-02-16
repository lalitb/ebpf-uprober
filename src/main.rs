use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::UprobeOpts;
use libbpf_rs::{MapFlags, OpenObject};
use std::path::Path;
use std::process::Command;

include!(concat!(env!("OUT_DIR"), "/uprober.skel.rs"));

fn main() {
    let skel_builder = UproberSkelBuilder::default();
    let mut skel = skel_builder.open().expect("Failed to open skeleton");

    skel.load().expect("Failed to load skeleton");

    let bash_path = Path::new("/bin/bash");
    // Open the binary to get a file descriptor
    let file = File::open(bash_path).expect("Failed to open binary");
    let binary_fd = file.as_raw_fd(); // Get the raw file descriptor

    let uprobe = skel.progs_mut().uprobe_readline();

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
