use url::Url;
use std::process::{Command, Child};

macro_rules! create_scan_common_function {
    ($name:ident, $command:expr, $($arg:expr),*) => {
        fn $name(&self) -> Child {
            let mut command = Command::new($command);
            let args = [$($arg,)*];
            let args = args.iter()
                .map(|&arg| if arg == "SELF" {self.as_str()} else {arg})
                .collect::<Vec<_>>();
            command.args(&args);
            let output = command.spawn()
                .expect(
                    &format!("Failed to execute command in the function {}", stringify!($name))
                    );
            output
        }
    }
}


trait PDToolBox {
    fn scan_dirsearch(&self) -> Child;
    fn scan_httpx(&self) -> Child;
    fn scan_katana(&self) -> Child;
    fn scan_nuclei(&self) -> Child;
    fn scan_waybackurls(&self) -> Child;
}

impl PDToolBox for Url {
    // Official url: https://github.com/maurosoria/dirsearch
    create_scan_common_function!(scan_dirsearch, "dirsearch", "-u", "SELF", "--format=plain", "-quiet");

    // Official url: https://github.com/projectdiscovery/httpx
    create_scan_common_function!(scan_httpx, "httpx-pd", "-sc", "-fr", "-title", "-u", "SELF", "-nc", "-silent");

    // Official url: https://github.com/projectdiscovery/katana
    create_scan_common_function!(scan_katana, "katana", "-u", "SELF");

    // Official url: https://github.com/projectdiscovery/nuclei
    create_scan_common_function!(scan_nuclei, "nuclei", "-nc", "-u", "SELF", "--silent");

    // Official url: https://github.com/tomnomnom/waybackurls
    create_scan_common_function!(scan_waybackurls, "waybackurls", "SELF");
}



fn main() {
    let url = Url::parse("https://e-aulas.urosario.edu.co").unwrap();
    let output = url.scan_httpx()
        .wait()
        .expect("failed on wait");

    println!("{:?}", output);


}
