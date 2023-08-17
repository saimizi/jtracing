#[allow(unused)]
use {
    cc,
    jlogger_tracing::{
        jdebug, jerror, jinfo, jtrace, jwarn, JloggerBuilder, LevelFilter, LogTimeFormat,
    },
    std::{
        env,
        fs::{self, canonicalize, create_dir_all, remove_file, File},
        os::unix::fs::symlink,
        path::{Path, PathBuf},
        process::{self, Command, Stdio},
        thread::available_parallelism,
    },
};

extern crate libbpf_cargo;
use libbpf_cargo::SkeletonBuilder;

fn build_zlib(compiler: &cc::Tool, install_dir: &PathBuf, build_log: &str) {
    jinfo!("CC {:?}", compiler.path());
    jinfo!("CFLAGS {:?}", compiler.cflags_env());

    let src_dir = canonicalize("third_party/zlib").expect("zlib source not found");
    let output = File::create(build_log).expect("Failed to create build log.");
    if !install_dir.exists() {
        fs::create_dir_all(&install_dir).expect("Failed to create install directory.");
    }
    jinfo!("Install_dir: {:?}", &install_dir);

    let status = Command::new("./configure")
        .arg("--static")
        .arg("--prefix")
        .arg(".")
        .arg("--libdir")
        .arg(&install_dir)
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output.try_clone().unwrap()))
        .env("CC", compiler.path())
        .env("CFLAGS", compiler.cflags_env())
        .current_dir(&src_dir)
        .status()
        .expect("Failed to do configure.");

    assert!(status.success(), "configure failed.");

    let status = Command::new("make")
        .arg("install")
        .arg("-j")
        .arg(&format!("{}", available_parallelism().unwrap().get()))
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output.try_clone().unwrap()))
        .current_dir(&src_dir)
        .status()
        .expect("Failed to do configure.");

    assert!(status.success(), "compile failed.");
}

fn build_elfutils(compiler: &cc::Tool, install_dir: &PathBuf, build_log: &str, target: &str) {
    jinfo!("CC {:?}", compiler.path());
    jinfo!("CFLAGS {:?}", compiler.cflags_env());

    let elfutils_src = canonicalize("third_party/elfutils").expect("elfutils source not found");
    let zlib_src = canonicalize("third_party/zlib").expect("zlib source not found");
    let output = File::create(build_log).expect("Failed to create build log.");
    jinfo!("Install_dir: {:?}", &install_dir);

    let makefile_path = elfutils_src.join("Makefile.am");
    let makefile = fs::read_to_string(&makefile_path).expect("Failed to read Makefile.am.");

    let fixed = makefile.replace(
        r#"
SUBDIRS = config lib libelf libcpu backends libebl libdwelf libdwfl libdw \
	  libasm debuginfod src po doc tests
"#,
        "SUBDIRS = config lib libelf backends",
    );

    fs::write(makefile_path, fixed).expect("Failed to write Makefile.am");

    let status = Command::new("autoreconf")
        .arg("--install")
        .arg("--force")
        .arg(".")
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output.try_clone().unwrap()))
        .current_dir(&elfutils_src)
        .status()
        .expect("Failed to do configure.");

    assert!(status.success(), "autoreconf failed.");

    let mut cflags = compiler.cflags_env().into_string().unwrap();
    cflags.push_str(&format!(" -I{}", zlib_src.as_path().to_str().unwrap()));
    let ldflags = format!(" -L{}", install_dir.as_path().to_str().unwrap());

    let mut build_args = vec![];
    build_args.push("--enable-maintainer-mode".to_string());
    build_args.push("--disable-debuginfod".to_string());
    build_args.push("--without-zstd".to_string());
    build_args.push("--disable-libdebuginfod".to_string());
    build_args.push("--disable-demangler".to_string());
    build_args.push("--prefix".to_string());
    build_args.push(install_dir.as_path().to_str().unwrap().to_string());
    build_args.push("--libdir".to_string());
    build_args.push(install_dir.as_path().to_str().unwrap().to_string());

    if target == "aarch64-unknown-linux-gnu" {
        let host = format!(
            "--host={}",
            compiler.path().to_str().unwrap().trim_end_matches("-gcc")
        );

        build_args.push(host);
    }

    let status = Command::new("./configure")
        .args(build_args)
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output.try_clone().unwrap()))
        .env("CC", compiler.path())
        .env("CFLAGS", &cflags)
        .env("CXXFLAGS", &cflags)
        .env("LDFLAGS", ldflags)
        .current_dir(&elfutils_src)
        .status()
        .expect("Failed to do configure.");

    assert!(status.success(), "configure failed.");

    let status = Command::new("make")
        .arg("install")
        .arg("libelf")
        .arg("-j")
        .arg(&format!("{}", available_parallelism().unwrap().get()))
        .arg("BUILD_STATIC_ONLY=y")
        .stdout(Stdio::from(output.try_clone().unwrap()))
        .stderr(Stdio::from(output.try_clone().unwrap()))
        .current_dir(&elfutils_src)
        .status()
        .expect("Failed to do configure.");

    assert!(status.success(), "compile failed.");
}

fn main() {
    JloggerBuilder::new()
        .max_level(LevelFilter::DEBUG)
        .log_file(Some(("/tmp/jtracing.log", false)))
        .log_console(false)
        .build();

    let applications = vec![
        "execsnoop_pb",
        "execsnoop_rb",
        "funccount",
        "eglswapbuffers",
        "profile",
        "bash_readline",
        "malloc_free",
    ];
    let out_dir = env::var("OUT_DIR").unwrap();

    jinfo!("{}", out_dir);

    let target = env::var("TARGET").unwrap();
    let compiler = cc::Build::new().get_compiler();
    let install_dir = PathBuf::from(&out_dir).join("objs");

    let build_log = "/tmp/build.log";
    let _ = remove_file(build_log);
    let _ = fs::remove_dir_all(&install_dir);
    fs::create_dir_all(&install_dir).expect("Failed to create install directory.");

    build_zlib(&compiler, &install_dir, build_log);
    build_elfutils(&compiler, &install_dir, build_log, &target);

    for &app in applications.iter() {
        let app_bpf_dir = format!("{}/bpf", app);
        let app_bpf_output_dir = format!("{}/{}/bpf/", out_dir, app);
        let skle_c = format!("{}/{}.bpf.c", app_bpf_dir, app);
        let mut vmlinux_inc = String::from("vmlinux/x86/");
        let skle_path = format!("{}/{}.skel.rs", app_bpf_output_dir, app);

        jinfo!("app_bpf_dir: {}", app_bpf_dir);
        jinfo!("app_bpf_output_dir: {}", app_bpf_output_dir);
        jinfo!("skle_c: {}", skle_c);
        jinfo!("skle_path: {}", skle_path);

        create_dir_all(&app_bpf_output_dir).unwrap();
        let skel = Path::new(&skle_path);
        let mut clang_args = String::from("-g -O2");
        if target == "aarch64-unknown-linux-gnu" {
            vmlinux_inc = vmlinux_inc.replace("x86", "arm64");
            clang_args.push_str(" -D__TARGET_ARCH_arm64")
        } else if target == "x86_64-unknown-linux-gnu" {
            clang_args.push_str(" -D__TARGET_ARCH_x86")
        }

        let cargo_search_path = format!("cargo:rustc-link-search={}", format!("{}/objs", out_dir));
        println!("{}", cargo_search_path);

        let abs_path_vmlinux_inc = canonicalize(vmlinux_inc).unwrap();
        clang_args.push_str(&format!(
            " -I{}",
            abs_path_vmlinux_inc.as_path().to_str().unwrap()
        ));

        jinfo!("clang_args: {}", clang_args);

        SkeletonBuilder::new()
            .source(&skle_c)
            .debug(true)
            .clang_args(&clang_args)
            .build_and_generate(skel)
            .expect("bpf compilation failed");
        println!("cargo:rerun-if-changed={}", &skle_c);
        println!("cargo:rerun-if-changed={}/{}.rs", app, app);

        let skle_path_dst = format!("{}/{}.skel.rs", app_bpf_dir, app);
        let _ = remove_file(&skle_path_dst);
        symlink(canonicalize(skle_path).unwrap(), skle_path_dst).unwrap();
    }
}
