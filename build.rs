use std::{
    env,
    fs::{create_dir_all, File},
    io::Write,
    process::Command,
};

use libbpf_cargo::SkeletonBuilder;
use memmap2::Mmap;

const FILTER_INCLUDE_PATH: &str = "src/core/filters/packets/bpf/include";

const INCLUDE_PATHS: [&str; 2] = [
    "src/core/probe/kernel/bpf/include",
    "src/core/events/bpf/include",
];

// Not super fail safe (not using Path).
fn get_paths(source: &str) -> (String, String) {
    let (dir, file) = source.rsplit_once('/').unwrap();
    let (name, _) = file.split_once('.').unwrap();

    let out = format!("{}/.out", dir);
    create_dir_all(out.as_str()).unwrap();

    (out, name.to_string())
}

fn build_hook(source: &str) {
    let (out, name) = get_paths(source);
    let output = format!("{}/{}.o", out.as_str(), name);
    let skel = format!("{}/{}.rs", out.as_str(), name);

    if let Err(e) = SkeletonBuilder::new()
        .source(source)
        .obj(output.as_str())
        .clang_args(
            INCLUDE_PATHS
                .iter()
                .map(|x| format!("-I{} ", x))
                .collect::<String>(),
        )
        .build()
    {
        panic!("{}", e);
    }

    let obj = File::open(output).unwrap();
    let obj: &[u8] = &unsafe { Mmap::map(&obj).unwrap() };

    let mut rs = File::create(skel).unwrap();
    write!(
        rs,
        r#"
           pub(crate) const DATA: &[u8] = &{:?};
           "#,
        obj
    )
    .unwrap();

    println!("cargo:rerun-if-changed={}", source);
}

fn build_probe(source: &str) {
    let (out, name) = get_paths(source);
    let skel = format!("{}/{}.skel.rs", out, name);

    if let Err(e) = SkeletonBuilder::new()
        .source(source)
        .clang_args(
            INCLUDE_PATHS
                .iter()
                .map(|x| format!("-I{} ", x))
                .collect::<String>(),
        )
        .build_and_generate(skel)
    {
        panic!("{}", e);
    }

    println!("cargo:rerun-if-changed={}", source);
}

fn gen_bindings() {
    let mut bindings = bindgen::Builder::default();
    const BINDGEN_HEADER: &str = "src/core/bpf_sys/include/bpf-sys.h";

    println!("cargo:rerun-if-changed={}", BINDGEN_HEADER);
    bindings = bindings
        .header(BINDGEN_HEADER);

    let builder = bindings
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Failed during bindings generation");

    builder
        .write_to_file(format!("{}/bpf_gen.rs", env::var("OUT_DIR").unwrap()))
        .expect("Failed writing bindings");
}

fn build_extract_stub() {
    const FILTER_STUB: &str = "src/core/filters/packets/bpf/stub.bpf.c";
    let (_, name) = get_paths(FILTER_STUB);
    let stub_base = format!("{}/{}", env::var("OUT_DIR").unwrap(), name);
    let stub_out = format!("{}.o", stub_base);

    if let Err(e) = SkeletonBuilder::new()
        .source(FILTER_STUB)
        .obj(&stub_out)
        .clang_args(format!("-I{} ", FILTER_INCLUDE_PATH))
        .build()
    {
        panic!("{}", e);
    }

    Command::new("llvm-objcopy")
        .args(["-O binary", "--set-section-flags .BTF=alloc", "-j .BTF", stub_out.as_str()])
        .arg(format!("{}.BTF", stub_base))
        .output()
        .expect("Failed to extract .BTF from stub ELF");

    Command::new("llvm-objcopy")
        .args(["-O binary", "--set-section-flags .BTF.ext=alloc", "-j .BTF.ext", stub_out.as_str()])
        .arg(format!("{}.BTF.ext", stub_base))
        .output()
        .expect("Failed to extract .BTF.ext from stub ELF");

    println!("cargo:rerun-if-changed={}", FILTER_STUB);
}

fn main() {
    gen_bindings();

    // core::probe::kernel
    build_probe("src/core/probe/kernel/bpf/kprobe.bpf.c");
    build_probe("src/core/probe/kernel/bpf/raw_tracepoint.bpf.c");

    // module::skb_tracking
    build_hook("src/module/skb_tracking/bpf/tracking_hook.bpf.c");

    build_extract_stub();

    for inc in INCLUDE_PATHS.iter() {
        println!("cargo:rerun-if-changed={}", inc);
    }
}
