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

    // Step 1: Generate vmlinux.h if missing
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

    // Step 2: Compile the eBPF program
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

    // Step 3: Strip debug symbols
    println!("Stripping eBPF binary...");
    let status = Command::new("llvm-strip")
        .args(["-g", &bpf_o_file])
        .status()
        .expect("Failed to strip eBPF binary");

    if !status.success() {
        eprintln!("Failed to strip eBPF binary");
        std::process::exit(1);
    }

    // Tell Cargo to watch for changes in the eBPF source files
    println!("cargo:rerun-if-changed={}", bpf_c_file);
    println!("cargo:rerun-if-changed={}", vmlinux_h_path);
}
