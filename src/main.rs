use url::Url;
mod scanners;

use scanners::ScannerToolBox;

fn main() {
    let url = Url::parse("https://e-aulas.urosario.edu.co").unwrap();
    let output = url.scanner_dirsearch()
        .wait()
        .expect("failed on wait");

    println!("{:?}", output);
}
