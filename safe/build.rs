use std::collections::BTreeSet;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const PACKAGE_VERSION: &str = "1.10.3";
const VERSION_NUMBER_HEX: &str = "0x010a03";
const LIBGCRYPT_CONFIG_API_VERSION: &str = "1";
const PREFIX: &str = "/usr";
const EXEC_PREFIX: &str = "/usr";
const INCLUDEDIR: &str = "/usr/include";
const BUILD_REVISION: &str = "aa161086";
const BUILD_TIMESTAMP: &str = "<none>";
const LIBGCRYPT_CIPHERS: &str = "arcfour blowfish cast5 des aes twofish serpent rfc2268 seed camellia idea salsa20 gost28147 chacha20 sm4";
const LIBGCRYPT_PUBKEY_CIPHERS: &str = "dsa elgamal rsa ecc";
const LIBGCRYPT_DIGESTS: &str = "crc gostr3411-94 md2 md4 md5 rmd160 sha1 sha256 sha512 sha3 tiger whirlpool stribog blake2 sm3";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let target_root = cargo_target_root(&out_dir)?;
    let multiarch = deb_host_multiarch();
    let abi_dir = manifest_dir.join("abi");
    let cabi_dir = manifest_dir.join("cabi");
    let bootstrap_dir = target_root.join("bootstrap");
    let generated_dir = bootstrap_dir.join("generated");
    let include_dir = generated_dir.join("include");
    let bin_dir = generated_dir.join("bin");
    let pkgconfig_dir = generated_dir.join("pkgconfig");
    let aclocal_dir = generated_dir.join("share").join("aclocal");

    for path in [&include_dir, &bin_dir, &pkgconfig_dir, &aclocal_dir] {
        fs::create_dir_all(path)?;
    }

    let gcrypt_h = render_gcrypt_header(&abi_dir.join("gcrypt.h.in"))?;
    let libgcrypt_config =
        render_libgcrypt_config(&abi_dir.join("libgcrypt-config.in"), &multiarch)?;
    let libgcrypt_pc = render_libgcrypt_pc(&abi_dir.join("libgcrypt.pc.in"), &multiarch)?;
    let symbols = parse_version_script(&abi_dir.join("libgcrypt.vers"))?;
    let c_stub_source = generate_c_stub_source(&symbols);

    write_if_changed(&include_dir.join("gcrypt.h"), &gcrypt_h)?;
    write_if_changed(&pkgconfig_dir.join("libgcrypt.pc"), &libgcrypt_pc)?;
    write_if_changed(&bin_dir.join("libgcrypt-config"), &libgcrypt_config)?;
    write_if_changed(&out_dir.join("generated_exports.c"), &c_stub_source)?;

    let aclocal_target = aclocal_dir.join("libgcrypt.m4");
    fs::copy(abi_dir.join("libgcrypt.m4"), &aclocal_target)?;
    #[cfg(unix)]
    {
        fs::set_permissions(
            bin_dir.join("libgcrypt-config"),
            fs::Permissions::from_mode(0o755),
        )?;
        fs::set_permissions(aclocal_target, fs::Permissions::from_mode(0o644))?;
    }

    compile_c_exports(
        &cabi_dir.join("exports.c"),
        &cabi_dir.join("exports.h"),
        &out_dir.join("generated_exports.c"),
        &include_dir,
        &out_dir,
    )?;

    println!(
        "cargo:rerun-if-changed={}",
        abi_dir.join("gcrypt.h.in").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        abi_dir.join("libgcrypt-config.in").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        abi_dir.join("libgcrypt.pc.in").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        abi_dir.join("libgcrypt.vers").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        abi_dir.join("libgcrypt.m4").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        cabi_dir.join("exports.c").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        cabi_dir.join("exports.h").display()
    );
    println!("cargo:rerun-if-env-changed=DEB_HOST_MULTIARCH");
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static:+whole-archive=safe_cabi");
    println!("cargo:rustc-link-lib=gmp");
    println!("cargo:rustc-link-lib=dl");
    if let Some(system_libgcrypt) = find_system_libgcrypt() {
        println!("cargo:rustc-env=SAFE_SYSTEM_LIBGCRYPT_PATH={system_libgcrypt}");
    }
    println!("cargo:rustc-cdylib-link-arg=-Wl,--no-gc-sections");
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libgcrypt.so.20");

    let build_manifest = format!(
        "BUILD_REVISION={BUILD_REVISION}\nBUILD_TIMESTAMP={BUILD_TIMESTAMP}\nGENERATED_INCLUDE={}\nGENERATED_PKGCONFIG={}\nGENERATED_CONFIG={}\n",
        include_dir.join("gcrypt.h").display(),
        pkgconfig_dir.join("libgcrypt.pc").display(),
        bin_dir.join("libgcrypt-config").display()
    );
    write_if_changed(&generated_dir.join("manifest.env"), &build_manifest)?;

    Ok(())
}

fn cargo_target_root(out_dir: &Path) -> io::Result<PathBuf> {
    let profile_dir = out_dir.ancestors().nth(3).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected OUT_DIR layout: {}", out_dir.display()),
        )
    })?;

    profile_dir.parent().map(Path::to_path_buf).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected OUT_DIR profile root: {}", out_dir.display()),
        )
    })
}

fn render_gcrypt_header(path: &Path) -> io::Result<String> {
    let template = fs::read_to_string(path)?;
    Ok(template
        .replace("@configure_input@", "safe/abi/gcrypt.h.in")
        .replace("@VERSION@", PACKAGE_VERSION)
        .replace("@VERSION_NUMBER@", VERSION_NUMBER_HEX))
}

fn deb_host_multiarch() -> String {
    env::var("DEB_HOST_MULTIARCH").unwrap_or_else(|_| "x86_64-linux-gnu".to_string())
}

fn render_libgcrypt_pc(path: &Path, multiarch: &str) -> io::Result<String> {
    let template = fs::read_to_string(path)?;
    let libdir = format!("/usr/lib/{multiarch}");
    Ok(template
        .replace("@prefix@", PREFIX)
        .replace("@exec_prefix@", EXEC_PREFIX)
        .replace("@includedir@", INCLUDEDIR)
        .replace("@libdir@", &libdir)
        .replace("@LIBGCRYPT_CONFIG_HOST@", multiarch)
        .replace(
            "@LIBGCRYPT_CONFIG_API_VERSION@",
            LIBGCRYPT_CONFIG_API_VERSION,
        )
        .replace("@LIBGCRYPT_CIPHERS@", LIBGCRYPT_CIPHERS)
        .replace("@LIBGCRYPT_PUBKEY_CIPHERS@", LIBGCRYPT_PUBKEY_CIPHERS)
        .replace("@LIBGCRYPT_DIGESTS@", LIBGCRYPT_DIGESTS)
        .replace("@PACKAGE_VERSION@", PACKAGE_VERSION)
        .replace("@LIBGCRYPT_CONFIG_CFLAGS@", "")
        .replace("@LIBGCRYPT_CONFIG_LIBS@", "-lgcrypt")
        .replace("@DL_LIBS@", ""))
}

fn render_libgcrypt_config(path: &Path, multiarch: &str) -> io::Result<String> {
    let template = fs::read_to_string(path)?;
    let libdir = format!("/usr/lib/{multiarch}");
    let rendered = template
        .replace("@configure_input@", "safe/abi/libgcrypt-config.in")
        .replace("@prefix@", PREFIX)
        .replace("@exec_prefix@", EXEC_PREFIX)
        .replace("@PACKAGE_VERSION@", PACKAGE_VERSION)
        .replace("@includedir@", INCLUDEDIR)
        .replace("@libdir@", &libdir)
        .replace("@GPG_ERROR_LIBS@", "-lgpg-error")
        .replace("@GPG_ERROR_CFLAGS@", "")
        .replace("@LIBGCRYPT_CONFIG_LIBS@", "-lgcrypt")
        .replace("@LIBGCRYPT_CONFIG_CFLAGS@", "")
        .replace(
            "@LIBGCRYPT_CONFIG_API_VERSION@",
            LIBGCRYPT_CONFIG_API_VERSION,
        )
        .replace("@LIBGCRYPT_CONFIG_HOST@", multiarch)
        .replace("@LIBGCRYPT_CIPHERS@", LIBGCRYPT_CIPHERS)
        .replace("@LIBGCRYPT_PUBKEY_CIPHERS@", LIBGCRYPT_PUBKEY_CIPHERS)
        .replace("@LIBGCRYPT_DIGESTS@", LIBGCRYPT_DIGESTS);

    Ok(rendered
        .replace(
            "    libs_final=\"$libs\"\n\n    # Set up `libdirs'.\n",
            "    libs_final=\"$libs\"\n    debianmultiarch=`if command -v dpkg-architecture > /dev/null ; then dpkg-architecture -qDEB_HOST_MULTIARCH ; fi`\n\n    # Set up `libdirs'.\n",
        )
        .replace(
            "if test \"x$libdir\" != \"x/usr/lib\" -a \"x$libdir\" != \"x/lib\"; then",
            "if test \"x$libdir\" != \"x/usr/lib\" -a \"x$libdir\" != \"x/lib\" -a \"x$libdir\" != \"x/usr/lib/${debianmultiarch}\" -a \"x$libdir\" != \"x/lib/${debianmultiarch}\" ; then",
        )
        .replace(
            "if test \"x$libdir\" != \"x/usr/lib\" -a \"x$libdir\" != \"x/lib\" -a \"x$libdir\" != \"x/lib/${debianmultiarch}\" ; then",
            "if test \"x$libdir\" != \"x/usr/lib\" -a \"x$libdir\" != \"x/lib\" -a \"x$libdir\" != \"x/usr/lib/${debianmultiarch}\" -a \"x$libdir\" != \"x/lib/${debianmultiarch}\" ; then",
        )
        .replace(
            "    libs_final=\"$libs_final $gpg_error_libs\"",
            "    #libs_final=\"$libs_final $gpg_error_libs\"\n    libs_final=\"-lgcrypt\"",
        ))
}

fn parse_version_script(path: &Path) -> io::Result<Vec<String>> {
    let text = fs::read_to_string(path)?;
    let mut symbols = Vec::new();
    let mut in_global = false;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("global:") {
            in_global = true;
            continue;
        }
        if trimmed.starts_with("local:") {
            break;
        }
        if !in_global || trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for token in trimmed.split(';') {
            let symbol = token.trim();
            if !symbol.is_empty() {
                symbols.push(symbol.to_string());
            }
        }
    }

    Ok(symbols)
}

fn generate_c_stub_source(symbols: &[String]) -> String {
    let handwritten: BTreeSet<&str> = BTreeSet::from([
        "gcry_check_version",
        "gcry_control",
        "gcry_set_progress_handler",
        "gcry_set_allocation_handler",
        "gcry_set_fatalerror_handler",
        "gcry_set_gettext_handler",
        "gcry_set_log_handler",
        "gcry_set_outofcore_handler",
        "gcry_err_code_from_errno",
        "gcry_err_code_to_errno",
        "gcry_err_make_from_errno",
        "gcry_error_from_errno",
        "gcry_strerror",
        "gcry_strsource",
        "gcry_free",
        "gcry_malloc",
        "gcry_malloc_secure",
        "gcry_calloc",
        "gcry_calloc_secure",
        "gcry_realloc",
        "gcry_strdup",
        "gcry_is_secure",
        "gcry_xcalloc",
        "gcry_xcalloc_secure",
        "gcry_xmalloc",
        "gcry_xmalloc_secure",
        "gcry_xrealloc",
        "gcry_xstrdup",
        "gcry_random_add_bytes",
        "gcry_random_bytes",
        "gcry_random_bytes_secure",
        "gcry_randomize",
        "gcry_create_nonce",
        "gcry_get_config",
        "gcry_md_get",
        "gcry_md_algo_info",
        "gcry_md_algo_name",
        "gcry_md_close",
        "gcry_md_copy",
        "gcry_md_ctl",
        "gcry_md_enable",
        "gcry_md_get_algo",
        "gcry_md_get_algo_dlen",
        "gcry_md_hash_buffer",
        "gcry_md_hash_buffers",
        "gcry_md_info",
        "gcry_md_is_enabled",
        "gcry_md_is_secure",
        "gcry_md_map_name",
        "gcry_md_open",
        "gcry_md_read",
        "gcry_md_extract",
        "gcry_md_reset",
        "gcry_md_setkey",
        "gcry_md_write",
        "gcry_md_debug",
        "gcry_cipher_algo_info",
        "gcry_cipher_algo_name",
        "gcry_cipher_close",
        "gcry_cipher_ctl",
        "gcry_cipher_decrypt",
        "gcry_cipher_encrypt",
        "gcry_cipher_get_algo_blklen",
        "gcry_cipher_get_algo_keylen",
        "gcry_cipher_info",
        "gcry_cipher_map_name",
        "gcry_cipher_mode_from_oid",
        "gcry_cipher_open",
        "gcry_cipher_setkey",
        "gcry_cipher_setiv",
        "gcry_cipher_setctr",
        "gcry_cipher_authenticate",
        "gcry_cipher_gettag",
        "gcry_cipher_checktag",
        "gcry_mac_algo_info",
        "gcry_mac_algo_name",
        "gcry_mac_map_name",
        "gcry_mac_get_algo",
        "gcry_mac_get_algo_maclen",
        "gcry_mac_get_algo_keylen",
        "gcry_mac_open",
        "gcry_mac_close",
        "gcry_mac_setkey",
        "gcry_mac_setiv",
        "gcry_mac_write",
        "gcry_mac_read",
        "gcry_mac_verify",
        "gcry_mac_ctl",
        "gcry_kdf_derive",
        "gcry_kdf_open",
        "gcry_kdf_compute",
        "gcry_kdf_final",
        "gcry_kdf_close",
        "gcry_log_debugmpi",
        "gcry_mpi_abs",
        "gcry_mpi_add",
        "gcry_mpi_add_ui",
        "gcry_mpi_addm",
        "gcry_mpi_aprint",
        "gcry_mpi_clear_bit",
        "gcry_mpi_clear_flag",
        "gcry_mpi_clear_highbit",
        "gcry_mpi_cmp",
        "gcry_mpi_cmp_ui",
        "gcry_mpi_copy",
        "gcry_mpi_div",
        "gcry_mpi_dump",
        "gcry_mpi_gcd",
        "gcry_mpi_get_flag",
        "gcry_mpi_get_nbits",
        "gcry_mpi_get_opaque",
        "gcry_mpi_get_ui",
        "gcry_mpi_invm",
        "gcry_mpi_is_neg",
        "gcry_mpi_lshift",
        "gcry_mpi_mod",
        "gcry_mpi_mul",
        "gcry_mpi_mul_2exp",
        "gcry_mpi_mul_ui",
        "gcry_mpi_mulm",
        "gcry_mpi_neg",
        "gcry_mpi_new",
        "gcry_mpi_powm",
        "gcry_mpi_print",
        "gcry_mpi_randomize",
        "gcry_mpi_release",
        "gcry_mpi_rshift",
        "gcry_mpi_scan",
        "gcry_mpi_set",
        "gcry_mpi_set_bit",
        "gcry_mpi_set_flag",
        "gcry_mpi_set_highbit",
        "gcry_mpi_set_opaque",
        "gcry_mpi_set_opaque_copy",
        "gcry_mpi_set_ui",
        "gcry_mpi_snatch",
        "gcry_mpi_snew",
        "gcry_mpi_sub",
        "gcry_mpi_sub_ui",
        "gcry_mpi_subm",
        "gcry_mpi_swap",
        "gcry_mpi_test_bit",
        "gcry_mpi_point_new",
        "gcry_mpi_point_release",
        "gcry_mpi_point_copy",
        "gcry_mpi_point_get",
        "gcry_mpi_point_snatch_get",
        "gcry_mpi_point_set",
        "gcry_mpi_point_snatch_set",
        "gcry_mpi_ec_new",
        "gcry_mpi_ec_get_mpi",
        "gcry_mpi_ec_get_point",
        "gcry_mpi_ec_set_mpi",
        "gcry_mpi_ec_set_point",
        "gcry_mpi_ec_decode_point",
        "gcry_mpi_ec_get_affine",
        "gcry_mpi_ec_dup",
        "gcry_mpi_ec_add",
        "gcry_mpi_ec_sub",
        "gcry_mpi_ec_mul",
        "gcry_mpi_ec_curve_point",
        "gcry_prime_check",
        "gcry_prime_generate",
        "gcry_prime_group_generator",
        "gcry_prime_release_factors",
        "gcry_ctx_release",
        "gcry_pk_algo_info",
        "gcry_pk_algo_name",
        "gcry_pk_ctl",
        "gcry_pk_decrypt",
        "gcry_pk_encrypt",
        "gcry_pk_genkey",
        "gcry_pk_get_keygrip",
        "gcry_pk_get_curve",
        "gcry_pk_get_param",
        "gcry_pk_get_nbits",
        "gcry_pk_map_name",
        "gcry_pk_register",
        "gcry_pk_sign",
        "gcry_pk_testkey",
        "gcry_pk_verify",
        "gcry_pubkey_get_sexp",
        "gcry_ecc_get_algo_keylen",
        "gcry_ecc_mul_point",
        "gcry_pk_hash_sign",
        "gcry_pk_hash_verify",
        "gcry_pk_random_override_new",
        "gcry_sexp_alist",
        "gcry_sexp_append",
        "gcry_sexp_build",
        "gcry_sexp_build_array",
        "gcry_sexp_cadr",
        "gcry_sexp_canon_len",
        "gcry_sexp_car",
        "gcry_sexp_cdr",
        "gcry_sexp_cons",
        "gcry_sexp_create",
        "gcry_sexp_dump",
        "gcry_sexp_find_token",
        "gcry_sexp_length",
        "gcry_sexp_new",
        "gcry_sexp_nth",
        "gcry_sexp_nth_buffer",
        "gcry_sexp_nth_data",
        "gcry_sexp_nth_mpi",
        "gcry_sexp_nth_string",
        "gcry_sexp_prepend",
        "gcry_sexp_release",
        "gcry_sexp_sprint",
        "gcry_sexp_sscan",
        "gcry_sexp_vlist",
        "gcry_sexp_extract_param",
        "_gcry_mpi_get_const",
        "gcry_log_debug",
    ]);

    let mut output = String::from(
        "/* @generated by build.rs */\n#include <stdint.h>\n\nextern uintptr_t safe_gcry_stub_zero(void);\n\n",
    );
    for symbol in symbols {
        if handwritten.contains(symbol.as_str()) {
            continue;
        }

        output.push_str(&format!(
            "uintptr_t {symbol}() {{ return safe_gcry_stub_zero(); }}\n"
        ));
    }
    output
}

fn compile_c_exports(
    manual_src: &Path,
    header: &Path,
    generated_src: &Path,
    include_dir: &Path,
    out_dir: &Path,
) -> io::Result<()> {
    let cc = env::var_os("CC").unwrap_or_else(|| OsString::from("cc"));
    let ar = env::var_os("AR").unwrap_or_else(|| OsString::from("ar"));
    let manual_object = out_dir.join("exports.o");
    let generated_object = out_dir.join("generated_exports.o");
    let archive_file = out_dir.join("libsafe_cabi.a");

    run(Command::new(&cc).args([
        OsString::from("-std=c11"),
        OsString::from("-fPIC"),
        OsString::from("-c"),
        manual_src.as_os_str().to_os_string(),
        OsString::from("-o"),
        manual_object.as_os_str().to_os_string(),
        OsString::from("-I"),
        include_dir.as_os_str().to_os_string(),
        OsString::from("-I"),
        header
            .parent()
            .expect("header has parent")
            .as_os_str()
            .to_os_string(),
        OsString::from("-I"),
        out_dir.as_os_str().to_os_string(),
    ]))?;

    run(Command::new(&cc).args([
        OsString::from("-std=c11"),
        OsString::from("-fPIC"),
        OsString::from("-c"),
        generated_src.as_os_str().to_os_string(),
        OsString::from("-o"),
        generated_object.as_os_str().to_os_string(),
    ]))?;

    if archive_file.exists() {
        fs::remove_file(&archive_file)?;
    }
    run(Command::new(&ar).args([
        OsString::from("crus"),
        archive_file.as_os_str().to_os_string(),
        manual_object.as_os_str().to_os_string(),
        generated_object.as_os_str().to_os_string(),
    ]))?;

    Ok(())
}

fn find_system_libgcrypt() -> Option<String> {
    let output = Command::new("ldconfig").arg("-p").output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.lines().find_map(|line| {
        if !line.contains("libgcrypt.so.20") {
            return None;
        }
        let path = line.split("=>").nth(1)?.trim();
        if path.is_empty() {
            None
        } else {
            Some(path.to_string())
        }
    })
}

fn run(command: &mut Command) -> io::Result<()> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("command failed: {command:?}")))
    }
}

fn write_if_changed(path: &Path, contents: &str) -> io::Result<()> {
    match fs::read_to_string(path) {
        Ok(existing) if existing == contents => return Ok(()),
        Ok(_) | Err(_) => {}
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, contents)
}
