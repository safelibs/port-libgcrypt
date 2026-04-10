use std::env;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::fs::File;
use std::io::{self, Read, Write};
use std::ptr::null_mut;

extern "C" {
    fn gcry_sexp_sscan(
        retsexp: *mut *mut c_void,
        erroff: *mut usize,
        buffer: *const c_char,
        length: usize,
    ) -> u32;
    fn gcry_sexp_sprint(
        sexp: *mut c_void,
        mode: c_int,
        buffer: *mut c_void,
        maxlength: usize,
    ) -> usize;
    fn gcry_sexp_release(sexp: *mut c_void);
}

const GCRYSEXP_FMT_DEFAULT: c_int = 0;
const GCRYSEXP_FMT_ADVANCED: c_int = 3;

struct Options {
    advanced: bool,
    assume_hex: bool,
    files: Vec<String>,
}

fn usage(mut out: impl Write) -> io::Result<()> {
    writeln!(out, "Usage: dumpsexp [OPTIONS] [file ...]")?;
    writeln!(out, "Debug tool for S-expressions")?;
    writeln!(out)?;
    writeln!(out, "  --decimal     accepted for compatibility")?;
    writeln!(out, "  --assume-hex  decode whitespace-separated hex input")?;
    writeln!(out, "  --advanced    print the advanced S-expression form")?;
    writeln!(out, "  --verbose     accepted for compatibility")?;
    writeln!(out, "  --version     print version information")?;
    writeln!(out, "  --help        display this help and exit")?;
    Ok(())
}

fn print_version() {
    println!("dumpsexp (Libgcrypt) 1.10.3");
}

fn parse_args() -> Result<Options, i32> {
    let mut advanced = false;
    let mut assume_hex = false;
    let mut files = Vec::new();

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
            "--advanced" => advanced = true,
            "--assume-hex" => assume_hex = true,
            "--decimal" | "--verbose" => {}
            "--" => {
                files.extend(args);
                break;
            }
            _ if arg.starts_with('-') => {
                eprintln!("dumpsexp: unknown option: {arg}");
                let _ = usage(io::stderr());
                return Err(1);
            }
            _ => files.push(arg),
        }
    }

    Ok(Options {
        advanced,
        assume_hex,
        files,
    })
}

fn read_input(path: Option<&str>) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    match path {
        Some(path) => File::open(path)?.read_to_end(&mut data)?,
        None => io::stdin().read_to_end(&mut data)?,
    };
    Ok(data)
}

fn decode_hex_dump(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut digits = Vec::new();
    for &byte in input {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return Err(format!("non-hex input byte 0x{byte:02x}"));
        }
        digits.push(byte);
    }
    if digits.len() % 2 != 0 {
        return Err("odd number of hex digits".to_string());
    }

    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let hi = hex_nibble(pair[0]).ok_or_else(|| "invalid hex digit".to_string())?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| "invalid hex digit".to_string())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
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

fn render_sexp(buffer: &[u8], advanced: bool) -> Result<Vec<u8>, String> {
    let mut sexp = null_mut();
    let mut erroff = 0usize;
    let err = unsafe {
        gcry_sexp_sscan(
            &mut sexp,
            &mut erroff,
            buffer.as_ptr().cast::<c_char>(),
            buffer.len(),
        )
    };
    if err != 0 {
        return Err(format!(
            "parse failed at offset {erroff}: {}",
            format_error(err)
        ));
    }

    let mode = if advanced {
        GCRYSEXP_FMT_ADVANCED
    } else {
        GCRYSEXP_FMT_DEFAULT
    };
    let needed = unsafe { gcry_sexp_sprint(sexp, mode, null_mut(), 0) };
    if needed == 0 {
        unsafe { gcry_sexp_release(sexp) };
        return Err("could not determine output size".to_string());
    }

    let mut out = vec![0u8; needed];
    let written = unsafe { gcry_sexp_sprint(sexp, mode, out.as_mut_ptr().cast(), out.len()) };
    unsafe { gcry_sexp_release(sexp) };
    if written == 0 {
        return Err("could not render S-expression".to_string());
    }
    out.truncate(written);
    Ok(out)
}

fn process_one(path: Option<&str>, options: &Options) -> Result<(), String> {
    let mut data = read_input(path).map_err(|err| {
        let display = path.unwrap_or("<stdin>");
        format!("could not read {display}: {err}")
    })?;
    if options.assume_hex {
        data = decode_hex_dump(&data)?;
    }

    let rendered = render_sexp(&data, options.advanced)?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&rendered)
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|err| err.to_string())
}

fn main() {
    let _ = gcrypt::gcry_check_version(std::ptr::null());

    let options = match parse_args() {
        Ok(options) => options,
        Err(code) => std::process::exit(code),
    };

    let result = if options.files.is_empty() {
        process_one(None, &options)
    } else {
        for path in &options.files {
            if let Err(err) = process_one(Some(path), &options) {
                eprintln!("dumpsexp: {err}");
                std::process::exit(1);
            }
        }
        Ok(())
    };

    if let Err(err) = result {
        eprintln!("dumpsexp: {err}");
        std::process::exit(1);
    }
}
