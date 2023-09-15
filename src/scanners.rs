use std::process::{Command, Child};
use url::Url;

#[derive(Debug)]
pub struct Scanner<'a> {
    command: & 'a str,
    args: Vec<& 'a str>,
}

pub enum ScannerType {
    Dirsearch,
    Httpx,
    Katana,
    Nuclei,
    Waybackurls
}

impl<'a> Scanner<'a>  {
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

pub trait ScannerToolBox {
    fn scanner_dirsearch(&self) -> Child;
    fn scanner_httpx(&self) -> Child;
    fn scanner_katana(&self) -> Child;
    fn scanner_nuclei(&self) -> Child;
    fn scanner_waybackurls(&self) -> Child;
}

impl ScannerToolBox for Url {
    create_scanner!(scanner_dirsearch, Scanner::new(ScannerType::Dirsearch));   // Official url: https://github.com/maurosoria/dirsearch
    create_scanner!(scanner_httpx, Scanner::new(ScannerType::Httpx));           // Official url: https://github.com/projectdiscovery/httpx
    create_scanner!(scanner_katana, Scanner::new(ScannerType::Katana));         // Official url: https://github.com/projectdiscovery/katana
    create_scanner!(scanner_nuclei, Scanner::new(ScannerType::Nuclei));         // Official url: https://github.com/projectdiscovery/nuclei
    create_scanner!(scanner_waybackurls, Scanner::new(ScannerType::Waybackurls));  // Official url: https://github.com/tomnomnom/waybackurls
}

