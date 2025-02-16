use libbpf_rs::{MapFlags, OpenObject, ProgType, UprobeAttachType};
use std::path::Path;
use std::process::Command;

fn main() {
    // Load and attach the eBPF program
    let skel_builder = uprober::UproberSkelBuilder::default();
    let mut skel = skel_builder.open().expect("Failed to open skeleton");

    // Load the eBPF program
    skel.load().expect("Failed to load skeleton");

    // Find the path to /bin/bash
    let bash_path = Path::new("/bin/bash");

    // Attach uprobe to readline() in bash
    skel.progs_mut()
        .uprobe_readline()
        .attach_uprobe(Some(bash_path), 0, "readline", UprobeAttachType::Entry)
        .expect("Failed to attach uprobe");

    println!("Uprobe attached! Now start /bin/bash and type a command.");

    // Print BPF logs
    loop {
        Command::new("bpftool")
            .arg("prog")
            .arg("tracelog")
            .status()
            .expect("Failed to read BPF logs");
    }
}