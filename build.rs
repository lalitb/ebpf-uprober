use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var("OUT_DIR").unwrap();
    let bpf_dir = "bpf";
    let vmlinux_h_path = format!("{}/vmlinux.h", bpf_dir);
    let bpf_c_file = format!("{}/uprober.bpf.c", bpf_dir);
    let bpf_o_file = format!("{}/uprober.bpf.o", out_dir);
    let skel_rs_file = format!("{}/uprober.skel.rs", out_dir);

    println!("OUT_DIR: {}", out_dir);

    // Generate vmlinux.h
    if !Path::new(&vmlinux_h_path).exists() {
        println!("Generating vmlinux.h...");
        let output = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .expect("Failed to run bpftool");

        if output.status.success() {
            fs::create_dir_all(bpf_dir).unwrap();
            fs::write(&vmlinux_h_path, output.stdout).unwrap();
            println!("Generated {}", vmlinux_h_path);
        } else {
            eprintln!("Error generating vmlinux.h: {:?}", output.stderr);
            std::process::exit(1);
        }
    }

    // Compile eBPF program
    fs::create_dir_all(&out_dir).unwrap();
    println!("Compiling eBPF program...");
    let status = Command::new("clang")
        .args([
            "-g",
            "-O2",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            "-c",
            &bpf_c_file,
            "-o",
            &bpf_o_file,
        ])
        .status()
        .expect("Failed to compile eBPF program");

    if !status.success() {
        eprintln!("Failed to compile eBPF program");
        std::process::exit(1);
    }

    println!("Generating uprober.skel.rs...");
    let status = Command::new("cargo-libbpf")
        .args(["libbpf", "gen", &bpf_o_file, "-o", &skel_rs_file])
        .status()
        .expect("Failed to generate skeleton");

    if !status.success() {
        eprintln!("Failed to generate skeleton");
        std::process::exit(1);
    }

    println!("cargo:rerun-if-changed={}", bpf_c_file);
}
