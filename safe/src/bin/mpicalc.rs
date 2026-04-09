use std::env;
use std::ffi::{CStr, CString, c_int, c_uint, c_void};
use std::io::{self, Read, Write};
use std::ptr::null_mut;

unsafe extern "C" {
    static mut stdout: *mut c_void;

    fn gcry_control(cmd: c_uint, ...) -> u32;
    fn gcry_mpi_new(nbits: c_uint) -> *mut c_void;
    fn gcry_mpi_release(a: *mut c_void);
    fn gcry_mpi_copy(a: *mut c_void) -> *mut c_void;
    fn gcry_mpi_scan(
        ret_mpi: *mut *mut c_void,
        format: c_int,
        buffer: *const c_void,
        buflen: usize,
        nscanned: *mut usize,
    ) -> u32;
    fn gcry_mpi_add(w: *mut c_void, u: *mut c_void, v: *mut c_void);
    fn gcry_mpi_aprint(
        format: c_int,
        buffer: *mut *mut u8,
        nbytes: *mut usize,
        a: *mut c_void,
    ) -> u32;
}

const GCRYCTL_DISABLE_SECMEM: c_uint = 37;
const GCRYCTL_INITIALIZATION_FINISHED: c_uint = 38;
const GCRYCTL_PRINT_CONFIG: c_uint = 53;
const GCRYMPI_FMT_HEX: c_int = 4;

fn usage(mut out: impl Write) -> io::Result<()> {
    writeln!(out, "Usage: mpicalc [options]")?;
    writeln!(out, "Simple interactive big integer RPN calculator")?;
    writeln!(out)?;
    writeln!(out, "Options:")?;
    writeln!(out, "  --version       print version information")?;
    writeln!(out, "  --print-config  print the Libgcrypt config")?;
    writeln!(out, "  --help          display this help and exit")?;
    Ok(())
}

fn print_version() {
    let version = unsafe {
        let ptr = gcrypt::gcry_check_version(std::ptr::null());
        if ptr.is_null() {
            "unknown".to_string()
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    };

    println!("mpicalc 2.0");
    println!("libgcrypt {version}");
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

fn parse_number(token: &str) -> Result<*mut c_void, String> {
    let mut text = String::new();
    if let Some(rest) = token.strip_prefix('-') {
        text.push_str("-0x");
        text.push_str(rest);
    } else {
        text.push_str("0x");
        text.push_str(token);
    }
    let c_text = CString::new(text).map_err(|err| err.to_string())?;
    let mut mpi = null_mut();
    let err = unsafe {
        gcry_mpi_scan(
            &mut mpi,
            GCRYMPI_FMT_HEX,
            c_text.as_ptr().cast(),
            0,
            null_mut(),
        )
    };
    if err != 0 {
        return Err(format_error(err));
    }
    if mpi.is_null() {
        return Err("gcry_mpi_scan returned NULL".to_string());
    }
    Ok(mpi)
}

fn print_top(stack: &[*mut c_void]) -> Result<(), String> {
    let Some(&top) = stack.last() else {
        println!("stack is empty");
        return Ok(());
    };

    let mut buffer = null_mut();
    let err = unsafe { gcry_mpi_aprint(GCRYMPI_FMT_HEX, &mut buffer, null_mut(), top) };
    if err != 0 {
        return Err(format_error(err));
    }
    if buffer.is_null() {
        return Err("gcry_mpi_aprint returned NULL".to_string());
    }

    unsafe {
        println!("{}", CStr::from_ptr(buffer.cast::<i8>()).to_string_lossy());
        gcrypt::gcry_free(buffer.cast());
    }
    Ok(())
}

fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    for line in input.lines() {
        let line = line.split('#').next().unwrap_or_default();
        tokens.extend(line.split_whitespace().map(ToOwned::to_owned));
    }
    tokens
}

fn run_repl(input: &str) -> Result<(), String> {
    let mut stack: Vec<*mut c_void> = Vec::new();

    for token in tokenize(input) {
        match token.as_str() {
            "+" => {
                if stack.len() < 2 {
                    eprintln!("stack underflow");
                    continue;
                }
                let rhs = stack.pop().expect("rhs");
                let lhs = *stack.last().expect("lhs");
                unsafe {
                    gcry_mpi_add(lhs, lhs, rhs);
                    gcry_mpi_release(rhs);
                }
            }
            "d" => {
                let Some(&top) = stack.last() else {
                    eprintln!("stack underflow");
                    continue;
                };
                let copy = unsafe { gcry_mpi_copy(top) };
                if copy.is_null() {
                    return Err("gcry_mpi_copy returned NULL".to_string());
                }
                stack.push(copy);
            }
            "c" => {
                for item in stack.drain(..) {
                    unsafe { gcry_mpi_release(item) };
                }
            }
            "p" => print_top(&stack)?,
            "f" => {
                for (index, item) in stack.iter().enumerate().rev() {
                    print!("[{index:2}]: ");
                    io::stdout().flush().map_err(|err| err.to_string())?;
                    print_top(std::slice::from_ref(item))?;
                }
            }
            "?" => {
                let _ = usage(io::stdout());
            }
            _ => stack.push(parse_number(&token)?),
        }
    }

    for item in stack {
        unsafe { gcry_mpi_release(item) };
    }
    Ok(())
}

fn main() {
    let mut print_config = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                let _ = usage(io::stdout());
                return;
            }
            "--version" => {
                print_version();
                return;
            }
            "--print-config" => print_config = true,
            "--" => {
                if args.next().is_some() {
                    eprintln!("mpicalc: unexpected trailing arguments");
                    std::process::exit(1);
                }
                break;
            }
            _ if arg.starts_with('-') => {
                eprintln!("mpicalc: unknown option: {arg}");
                std::process::exit(1);
            }
            _ => {
                eprintln!("mpicalc: unexpected argument: {arg}");
                std::process::exit(1);
            }
        }
    }

    let _ = gcrypt::gcry_check_version(std::ptr::null());
    unsafe {
        let _ = gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
        let _ = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    }

    if print_config {
        unsafe {
            let _ = gcry_control(GCRYCTL_PRINT_CONFIG, stdout);
        }
        return;
    }

    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        eprintln!("mpicalc: {err}");
        std::process::exit(1);
    }

    if let Err(err) = run_repl(&input) {
        eprintln!("mpicalc: {err}");
        std::process::exit(1);
    }
}
