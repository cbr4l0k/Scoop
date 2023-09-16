use std::process::{Command, Child};
use url::Url;

/// `Scanner` represents a security scanner command and its arguments.
///
/// # Example
/// ```
/// let scanner = Scanner { command: "nmap", args: vec!["-p", "80,443", "localhost"]};
/// ```
#[derive(Debug)]
pub struct Scanner<'a> {
    command: & 'a str,
    args: Vec<& 'a str>,
}

/// `ScannerType` represents the types of scanners that can be created. 
/// Each variant corresponds to a specific security scanner.
pub enum ScannerType {
    Dirsearch,
    Httpx,
    Katana,
    Nuclei,
    Waybackurls,
    Subfinder,
    Naabu
}

impl<'a> Scanner<'a>  {
    /// Creates a new `Scanner` based on the provided `ScannerType`.
    ///
    /// # Example
    /// ```
    /// let scanner = Scanner::new(ScannerType::Dirsearch);
    /// ```
    fn new(scanner_type: ScannerType) -> Self {
        match scanner_type {
            ScannerType::Dirsearch => Scanner {
                command: "dirsearch",
                args: vec!["-u", "URL", "--format=plain", "-quiet"]
            },
            ScannerType::Httpx => Scanner {
                command: "httpx-pd",
                args: vec!["-sc", "-fr", "-title", "-u", "URL", "-nc", "-silent"]
            },
            ScannerType::Katana => Scanner {
                command: "katana",
                args: vec!["-u", "URL"]
            },
            ScannerType::Nuclei => Scanner {
                command: "nuclei",
                args: vec!["-nc", "-u", "URL", "--silent"]
            },
            ScannerType::Waybackurls => Scanner {
                command: "waybackurls",
                args: vec!["URL"]
            }, 
            ScannerType::Subfinder => Scanner {
                command: "subfinder",
                args: vec!["-d", "HOST", "--silent"]
            },
            ScannerType::Naabu => Scanner {
                command: "naabu",
                args: vec!["-host", "HOST", "--silent"]
            }
        }
    }
}

macro_rules! create_scanner {
    ($name:ident, $st:expr) => {
        fn $name(&self) -> Child {
            let mut command = Command::new($st.command);
            let args = $st.args.iter()
                .map(|&arg| {
                    match arg {
                        "URL" => self.as_str(),
                        "HOST" => self.host_str().expect(&format!(
                        "Failed to get the host in the function {}", 
                        stringify!($name)
                )),
                        _ => arg,
                    } 
                }).collect::<Vec<&str>>();
            command.args(&args);
            let output = command.spawn()
                .expect(&format!(
                        "Failed to execute command in the function {}", 
                        stringify!($name)
                ));
            output
        }
    };
}

/// `ScannerToolBox` is a trait that proves methods to scan URLs using  different security
/// scanners.
pub trait ScannerToolBox {
    fn scanner_dirsearch(&self) -> Child;
    fn scanner_httpx(&self) -> Child;
    fn scanner_katana(&self) -> Child;
    fn scanner_nuclei(&self) -> Child;
    fn scanner_waybackurls(&self) -> Child;
    fn scanner_subfinder(&self) -> Child;
    fn scanner_naabu(&self) -> Child;
}

impl ScannerToolBox for Url {
    create_scanner!(scanner_dirsearch, Scanner::new(ScannerType::Dirsearch));       // Official url: https://github.com/maurosoria/dirsearch
    create_scanner!(scanner_httpx, Scanner::new(ScannerType::Httpx));               // Official url: https://github.com/projectdiscovery/httpx
    create_scanner!(scanner_katana, Scanner::new(ScannerType::Katana));             // Official url: https://github.com/projectdiscovery/katana
    create_scanner!(scanner_nuclei, Scanner::new(ScannerType::Nuclei));             // Official url: https://github.com/projectdiscovery/nuclei
    create_scanner!(scanner_waybackurls, Scanner::new(ScannerType::Waybackurls));   // Official url: https://github.com/tomnomnom/waybackurls
    create_scanner!(scanner_subfinder, Scanner::new(ScannerType::Subfinder));       // Official url: https://github.com/projectdiscovery/subfinder
    create_scanner!(scanner_naabu, Scanner::new(ScannerType::Naabu));               // Official url: https://github.com/projectdiscovery/naabu
}

