use std::env;
use std::ffi::{CStr, c_int, c_uint, c_void};
use std::fs::File;
use std::io::{self, Read, Write};
use std::ptr::null_mut;

extern "C" {
    fn gcry_md_open(handle: *mut *mut c_void, algo: c_int, flags: c_uint) -> u32;
    fn gcry_md_close(handle: *mut c_void);
    fn gcry_md_setkey(handle: *mut c_void, key: *const c_void, keylen: usize) -> u32;
    fn gcry_md_write(handle: *mut c_void, buffer: *const c_void, length: usize);
    fn gcry_md_read(handle: *mut c_void, algo: c_int) -> *mut u8;
    fn gcry_md_ctl(handle: *mut c_void, cmd: c_int, buffer: *mut c_void, buflen: usize) -> u32;
}

const GCRY_MD_SHA256: c_int = 8;
const GCRY_MD_FLAG_HMAC: c_uint = 2;
const GCRYCTL_FINALIZE: c_int = 5;
const STANDARD_KEY: &str = "What am I, a doctor or a moonshuttle conductor?";

struct Options {
    binary: bool,
    key: Vec<u8>,
    files: Vec<String>,
}

fn usage(mut out: impl Write) -> io::Result<()> {
    writeln!(
        out,
        "Usage: hmac256 [--binary] [--stdkey|key] [filename ...]"
    )?;
    writeln!(out, "Compute HMAC-SHA256 digests with libgcrypt")?;
    Ok(())
}

fn print_version() {
    println!("hmac256 (Libgcrypt) 1.10.3");
}

fn parse_args() -> Result<Options, i32> {
    let mut binary = false;
    let mut stdkey = false;
    let mut positional = Vec::new();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                let _ = usage(io::stdout());
                return Err(0);
            }
            "--version" => {
                print_version();
                return Err(0);
            }
            "--binary" => binary = true,
            "--stdkey" => stdkey = true,
            "--" => {
                positional.extend(args);
                break;
            }
            _ if arg.starts_with('-') => {
                eprintln!("hmac256: unknown option: {arg}");
                let _ = usage(io::stderr());
                return Err(1);
            }
            _ => positional.push(arg),
        }
    }

    let key = if stdkey {
        STANDARD_KEY.as_bytes().to_vec()
    } else if !positional.is_empty() {
        positional.remove(0).into_bytes()
    } else {
        let _ = usage(io::stderr());
        return Err(1);
    };

    Ok(Options {
        binary,
        key,
        files: positional,
    })
}

fn format_error(code: u32) -> String {
    unsafe {
        let ptr = gcrypt::gcry_strerror(code);
        if ptr.is_null() {
            return format!("error {code}");
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

fn compute_hmac(mut reader: impl Read, key: &[u8]) -> Result<[u8; 32], String> {
    let mut handle = null_mut();
    let err = unsafe { gcry_md_open(&mut handle, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC) };
    if err != 0 {
        return Err(format!("gcry_md_open failed: {}", format_error(err)));
    }

    let err = unsafe { gcry_md_setkey(handle, key.as_ptr().cast(), key.len()) };
    if err != 0 {
        unsafe { gcry_md_close(handle) };
        return Err(format!("gcry_md_setkey failed: {}", format_error(err)));
    }

    let mut buffer = [0u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        unsafe {
            gcry_md_write(handle, buffer.as_ptr().cast(), read);
        }
    }

    let err = unsafe { gcry_md_ctl(handle, GCRYCTL_FINALIZE, null_mut(), 0) };
    if err != 0 {
        unsafe { gcry_md_close(handle) };
        return Err(format!(
            "gcry_md_ctl(FINALIZE) failed: {}",
            format_error(err)
        ));
    }

    let mut digest = [0u8; 32];
    let ptr = unsafe { gcry_md_read(handle, GCRY_MD_SHA256) };
    if ptr.is_null() {
        unsafe { gcry_md_close(handle) };
        return Err("gcry_md_read returned NULL".to_string());
    }
    unsafe {
        std::ptr::copy_nonoverlapping(ptr, digest.as_mut_ptr(), digest.len());
        gcry_md_close(handle);
    }
    Ok(digest)
}

fn process_path(path: Option<&str>, options: &Options) -> Result<(), String> {
    let digest = match path {
        Some(path) => compute_hmac(
            File::open(path).map_err(|err| err.to_string())?,
            &options.key,
        )?,
        None => compute_hmac(io::stdin().lock(), &options.key)?,
    };

    let mut stdout = io::stdout().lock();
    if options.binary {
        stdout.write_all(&digest).map_err(|err| err.to_string())
    } else {
        for byte in digest {
            write!(stdout, "{byte:02x}").map_err(|err| err.to_string())?;
        }
        writeln!(stdout, "  {}", path.unwrap_or("-")).map_err(|err| err.to_string())
    }
}

fn main() {
    let _ = gcrypt::gcry_check_version(std::ptr::null());

    let options = match parse_args() {
        Ok(options) => options,
        Err(code) => std::process::exit(code),
    };

    if options.files.is_empty() {
        if let Err(err) = process_path(None, &options) {
            eprintln!("hmac256: {err}");
            std::process::exit(1);
        }
        return;
    }

    for path in &options.files {
        if let Err(err) = process_path(Some(path), &options) {
            eprintln!("hmac256: {path}: {err}");
            std::process::exit(1);
        }
    }
}
