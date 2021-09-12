// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use alloc::string::String;

pub(crate) fn rfc_to_json(input: &str) -> String {
    format!("{{\n{}\n}}", parse_ciphersuites(input))
}

fn parse_ciphersuites(input: &str) -> String {
    let re = regex::Regex::new(r"## OPRF\((?P<ciphersuite>.+?)\)").unwrap();
    let mut ciphersuites = vec![];

    let chunks: Vec<&str> = re.split(input).collect();
    let mut count = 1;
    for caps in re.captures_iter(input) {
        let ciphersuite = format!(
            "\"{}\": {{ {} }}",
            caps["ciphersuite"].to_string(),
            parse_modes(chunks[count])
        );
        ciphersuites.push(ciphersuite);
        count += 1;
    }

    ciphersuites.join(",\n")
}

fn parse_modes(input: &str) -> String {
    let re = regex::Regex::new(r"### (?P<mode>.*+) Mode").unwrap();
    let mut modes = vec![];

    let chunks: Vec<&str> = re.split(input).collect();
    let mut count = 1;
    for caps in re.captures_iter(input) {
        let mode = format!(
            "\"{}\": [\n {} \n]",
            caps["mode"].to_string(),
            parse_vectors(chunks[count])
        );
        modes.push(mode);
        count += 1;
    }

    modes.join(",\n")
}

fn parse_vectors(input: &str) -> String {
    let re = regex::Regex::new(r"Test Vector.*+\n").unwrap();
    let mut vectors = vec![];

    let chunks: Vec<&str> = re.split(input).collect();
    let init_params = parse_params(chunks[0]);

    let mut count = 1;
    for _ in re.captures_iter(input) {
        let params = format!("{{\n{},\n{}\n}}", init_params, parse_params(chunks[count]));
        vectors.push(params);
        count += 1;
    }

    vectors.join(",\n")
}

fn parse_params(input: &str) -> String {
    let mut params = vec![];
    let mut param = String::new();

    let mut lines = input.lines();

    loop {
        match lines.next() {
            None => {
                // Clear out any existing string and flush to params
                param += "\"";
                params.push(param);

                return params.join(",\n");
            }
            Some(line) => {
                // If line contains =, then
                if line.contains('=') {
                    // Clear out any existing string and flush to params
                    if param.len() > 0 {
                        param += "\"";
                        params.push(param);
                    }

                    let mut iter = line.split('=');
                    let key = iter.next().unwrap().split_whitespace().next().unwrap();
                    let val = iter.next().unwrap().split_whitespace().next().unwrap();

                    param = format!("    \"{}\": \"{}", key, val);
                } else {
                    let s = line.trim().to_string();
                    if s.contains("~") || s.contains("#") {
                        // Ignore comment lines
                        continue;
                    }
                    if s.len() > 0 {
                        param += &s;
                    }
                }
            }
        }
    }
}
