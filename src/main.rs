use libbpf_rs::{MapFlags, OpenObject};
use std::path::Path;
use std::process::Command;
include!(concat!(env!("OUT_DIR"), "/uprober.skel.rs"));

fn main() {
    let skel_builder = UproberSkelBuilder::default();
    let mut skel = skel_builder.open().expect("Failed to open skeleton");

    skel.load().expect("Failed to load skeleton");

    let bash_path = Path::new("/bin/bash");

    skel.progs_mut()
        .uprobe_readline()
        .attach_uprobe_opts(UprobeOpts {
            binary_path: bash_path.to_string_lossy().into_owned(),
            func_offset: 0,
            func_name: "readline".into(),
            retprobe: false, // false for entry, true for return probes
            pid: None,
        })
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
