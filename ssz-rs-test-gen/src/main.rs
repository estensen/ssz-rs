//! Code generation utility for consuming consensus spec tests relevant to the `ssz_rs` crate.
//! Not user facing.
#![doc(hidden)]

use convert_case::{Case, Casing};
use num_bigint::BigUint;
use std::{collections::BTreeMap, env, ffi::OsStr, fmt, fs, fs::DirEntry, path::PathBuf};

const DRY_RUN: bool = false;
const SRC_DIR: &str = "consensus-spec-tests/tests/general/phase0/ssz_generic/";
const TARGET_DIR: &str = "../ssz-rs/tests/";

const SRC_PREAMBLE: &str = r#"//! This file was generated by `ssz-rs-test-gen`; do NOT manually edit.
mod test_utils;

use ssz_rs::prelude::*;
use test_utils::{
    deserialize, hash_tree_root, read_ssz_snappy_from_test_data, root_from_hex, serialize,
};
"#;

const CONTAINERS_DEFN_FMT: &str = r#"
#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
struct SingleFieldTestStruct {
    a: u8,
}

#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
struct SmallTestStruct {
    a: u16,
    b: u16,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
struct FixedTestStruct {
    a: u8,
    b: u64,
    c: u32,
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
struct VarTestStruct {
    a: u16,
    b: List<u16, 1024>,
    c: u8,
}

#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
struct ComplexTestStruct {
    a: u16,
    b: List<u16, 128>,
    c: u8,
    d: List<u8, 256>,
    e: VarTestStruct,
    f: Vector<FixedTestStruct, 4>,
    g: Vector<VarTestStruct, 2>,
}

#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
struct BitsStruct {
    a: Bitlist<5>,
    b: Bitvector<2>,
    c: Bitvector<1>,
    d: Bitlist<6>,
    e: Bitvector<8>,
}
"#;

#[derive(Clone, Copy, Debug)]
enum SszType {
    BasicVector,
    Bitlist,
    Bitvector,
    Boolean,
    Container,
    Uint,
}

impl From<&str> for SszType {
    fn from(value: &str) -> Self {
        match value {
            "basic_vector" => Self::BasicVector,
            "bitlist" => Self::Bitlist,
            "bitvector" => Self::Bitvector,
            "boolean" => Self::Boolean,
            "containers" => Self::Container,
            "uints" => Self::Uint,
            other => panic!("unsupported type: {other}"),
        }
    }
}

impl fmt::Display for SszType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BasicVector => write!(f, "basic_vector"),
            Self::Bitlist => write!(f, "bitlist"),
            Self::Bitvector => write!(f, "bitvector"),
            Self::Boolean => write!(f, "boolean"),
            Self::Container => write!(f, "containers"),
            Self::Uint => write!(f, "uints"),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
enum Format {
    #[default]
    Valid,
    Invalid,
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Invalid => write!(f, "invalid"),
        }
    }
}

fn to_string(s: &OsStr) -> String {
    s.to_str().unwrap().to_string()
}

fn read_yaml(path: &PathBuf) -> serde_yaml::Value {
    let contents = fs::read_to_string(path).unwrap();
    serde_yaml::from_str(&contents).unwrap()
}

fn do_create(path: PathBuf) -> Box<dyn std::io::Write> {
    if DRY_RUN {
        Box::<Vec<u8>>::default()
    } else {
        Box::new(fs::File::create(path).unwrap())
    }
}

fn do_write<F: std::io::Write>(mut f: F, text: String) {
    if DRY_RUN {
        println!("{}", text);
    } else {
        write!(f, "{text}").expect("can write");
    }
}

fn do_copy(src: &PathBuf, target: &PathBuf) {
    if DRY_RUN {
        let src = src.display();
        let target = target.display();
        println!("moving files from {src} to {target}");
    } else {
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::copy(src, target).expect("can copy");
    }
}

fn to_rust_u256(value: &serde_yaml::Value) -> String {
    let value = value.as_str().unwrap();
    let x = value.parse::<BigUint>().unwrap();
    let mut x_bytes = x.to_bytes_le();
    assert!(x_bytes.len() <= 32);
    x_bytes.resize(32, 0);
    format!("U256::try_from_le_slice(Vec::<u8>::from_iter({x_bytes:?}).as_ref()).unwrap()")
}

fn to_rust_bitvector(value: &serde_yaml::Value, rust_type: &str) -> String {
    let data = value.as_str().unwrap();
    let bytes = hex::decode(data.strip_prefix("0x").unwrap()).unwrap();
    format!("<{rust_type} as TryFrom<&[u8]>>::try_from(Vec::<u8>::from_iter({bytes:?}).as_ref()).unwrap()")
}

fn to_rust_bitlist(value: &serde_yaml::Value, rust_type: &str) -> String {
    let data = value.as_str().unwrap();
    let bytes = hex::decode(data.strip_prefix("0x").unwrap()).unwrap();
    format!("<{rust_type} as TryFrom<&[u8]>>::try_from(Vec::<u8>::from_iter({bytes:?}).as_ref()).unwrap()")
}

fn to_rust_vector(value: serde_yaml::Value, rust_type: &str) -> String {
    if rust_type.contains("U256") {
        let values = value.as_sequence().unwrap();
        let values = values.iter().map(to_rust_u256).collect::<Vec<_>>();
        let inner = values.join(", ");
        format!("{rust_type}::try_from(Vec::<U256>::from_iter([{inner}])).unwrap()")
    } else if rust_type.contains("u128") {
        let values = value.as_sequence().unwrap();
        let values =
            values.iter().map(|v| v.as_str().unwrap().trim().to_string()).collect::<Vec<_>>();
        let inner = values.join(", ");
        format!("{rust_type}::try_from(Vec::<u128>::from_iter([{inner}])).unwrap()")
    } else {
        let parts = rust_type.split('<').collect::<Vec<_>>();
        let inner = parts[1].split(',').collect::<Vec<_>>();
        let inner_type = inner[0];
        let inner_seq = value.as_sequence().unwrap();
        let inner_values = inner_seq.iter().map(value_to_compact_string).collect::<Vec<_>>();

        let inner_value = inner_values.join(", ");
        format!("{rust_type}::try_from(Vec::<{inner_type}>::from_iter([{inner_value}])).unwrap()")
    }
}

fn value_to_compact_string(v: &serde_yaml::Value) -> String {
    serde_yaml::to_string(v).unwrap().trim().to_string()
}

fn to_field_value(key: &str, value: &serde_yaml::Value, rust_type: &str) -> String {
    match rust_type {
        "VarTestStruct" => {
            if key == "b" {
                let values = value
                    .as_sequence()
                    .unwrap()
                    .iter()
                    .map(value_to_compact_string)
                    .collect::<Vec<_>>();
                let inner = values.join(", ");
                format!("List::<u16, 1024>::try_from(Vec::<u16>::from_iter([{inner}])).unwrap()")
            } else {
                value_to_compact_string(value)
            }
        }
        "ComplexTestStruct" => match key {
            "b" => {
                let values = value
                    .as_sequence()
                    .unwrap()
                    .iter()
                    .map(value_to_compact_string)
                    .collect::<Vec<_>>();
                let inner = values.join(", ");
                format!("List::<u16, 128>::try_from(Vec::<u16>::from_iter([{inner}])).unwrap()")
            }
            "d" => {
                let data = value.as_str().unwrap();

                let bytes = hex::decode(data.strip_prefix("0x").unwrap()).unwrap();
                format!("List::<u8, 256>::try_from(Vec::<u8>::from_iter({bytes:?})).unwrap()")
            }
            "e" => to_rust_struct(value.clone(), "VarTestStruct"),
            "f" => {
                let values = value
                    .as_sequence()
                    .unwrap()
                    .iter()
                    .map(|v| to_rust_struct(v.clone(), "FixedTestStruct"))
                    .collect::<Vec<_>>();
                let inner = values.join(", ");
                format!("Vector::<FixedTestStruct, 4>::try_from(vec![{inner}]).unwrap()")
            }
            "g" => {
                let values = value
                    .as_sequence()
                    .unwrap()
                    .iter()
                    .map(|v| to_rust_struct(v.clone(), "VarTestStruct"))
                    .collect::<Vec<_>>();
                let inner = values.join(", ");
                format!("Vector::<VarTestStruct, 2>::try_from(vec![{inner}]).unwrap()")
            }
            _ => value_to_compact_string(value),
        },
        "BitsStruct" => match key {
            "a" => to_rust_bitlist(value, "Bitlist::<5>"),
            "b" => to_rust_bitvector(value, "Bitvector::<2>"),
            "c" => to_rust_bitvector(value, "Bitvector::<1>"),
            "d" => to_rust_bitlist(value, "Bitlist::<6>"),
            "e" => to_rust_bitvector(value, "Bitvector::<8>"),
            other => unimplemented!("unsupported field {other} for `BitsStruct`"),
        },
        _ => value_to_compact_string(value),
    }
}

fn to_rust_struct(value: serde_yaml::Value, rust_type: &str) -> String {
    let mut inline = vec![];
    let mapping = value.as_mapping().unwrap();
    for (k, v) in mapping {
        let key = k.as_str().unwrap().to_lowercase();
        let value = to_field_value(&key, v, rust_type);
        let field = format!("{key}: {value}");
        inline.push(field);
    }
    let inline = inline.join(", ");
    format!("{rust_type}{{{inline}}}")
}

fn to_rust_value(name: &str, rust_type: &str, value: serde_yaml::Value) -> String {
    if name.contains("uint_256") {
        to_rust_u256(&value)
    } else if name.contains("bitvec") {
        to_rust_bitvector(&value, rust_type)
    } else if name.contains("bitlist") {
        to_rust_bitlist(&value, rust_type)
    } else if name.contains("vec_") {
        to_rust_vector(value, rust_type)
    } else if [
        "SingleFieldTestStruct",
        "SmallTestStruct",
        "FixedTestStruct",
        "VarTestStruct",
        "ComplexTestStruct",
        "BitsStruct",
    ]
    .iter()
    .any(|&target| name.contains(target))
    {
        to_rust_struct(value, rust_type)
    } else {
        let value = value_to_compact_string(&value);
        value.trim_matches('\'').to_string()
    }
}

fn to_element_type(s: &str) -> String {
    match s {
        "bool" => s.to_string(),
        "uint256" => "U256".to_string(),
        s => {
            let width = &s[4..];
            format!("u{width}")
        }
    }
}

fn to_rust_type(ssz_type: SszType, name: &str) -> String {
    match ssz_type {
        SszType::BasicVector => {
            let parts = name.split('_').collect::<Vec<&str>>();
            let element_type = to_element_type(parts[1]);
            let length = parts[2];
            format!("Vector::<{element_type}, {length}>")
        }
        SszType::Bitlist => {
            let parts = name.split('_').collect::<Vec<&str>>();
            let bound = parts[1];
            if bound == "no" {
                "Bitlist::<256>".to_string()
            } else {
                format!("Bitlist::<{bound}>")
            }
        }
        SszType::Bitvector => {
            let parts = name.split('_').collect::<Vec<&str>>();
            let bound = parts[1];
            format!("Bitvector::<{bound}>")
        }
        SszType::Boolean => "bool".to_string(),
        SszType::Container => {
            let parts = name.split('_').collect::<Vec<&str>>();
            parts[0].to_string()
        }
        SszType::Uint => {
            let parts = name.split('_').collect::<Vec<&str>>();
            let width = parts[1];
            if width.contains("256") {
                "U256".to_string()
            } else {
                format!("u{width}")
            }
        }
    }
}

#[derive(Default, Debug)]
struct TestCase {
    // hash tree root if provided in `meta`
    root: Option<String>,
    value: Option<serde_yaml::Value>,
    data_path: Option<PathBuf>,
    format: Format,
}

#[derive(Debug)]
struct Generator {
    ssz_type: SszType,
    components: Vec<String>,
    test_cases: BTreeMap<String, TestCase>,
}

impl Generator {
    fn new(ssz_type: SszType) -> Self {
        let mut components = vec![SRC_PREAMBLE.to_string()];
        if matches!(ssz_type, SszType::Container) {
            components.push(CONTAINERS_DEFN_FMT.to_string());
        }
        Self { ssz_type, components, test_cases: Default::default() }
    }

    fn load_test_case(&mut self, format: Format, path: DirEntry) {
        let path = path.path();
        let test_case = to_string(path.file_name().unwrap());
        let test_case = self.test_cases.entry(test_case).or_default();
        test_case.format = format;
        for part in fs::read_dir(&path).unwrap() {
            match part {
                Ok(path) => {
                    let part_name = to_string(&path.file_name());
                    let path = path.path();
                    if part_name.contains("meta") {
                        let value = read_yaml(&path);
                        let root =
                            value.as_mapping().unwrap().get("root").unwrap().as_str().unwrap();
                        test_case.root = Some(root.to_string());
                    } else if part_name.contains("value") {
                        let value = read_yaml(&path);
                        test_case.value = Some(value);
                    } else {
                        assert!(part_name.contains("ssz_snappy"));
                        test_case.data_path = Some(path);
                    }
                }
                Err(err) => panic!("{err}"),
            }
        }
    }

    fn execute(self) {
        let target_dir = PathBuf::from(TARGET_DIR);
        let ssz_type = self.ssz_type.to_string();
        let mut target_file_path = target_dir.join(&ssz_type);
        target_file_path.set_extension("rs");
        let mut target_file = do_create(target_file_path);
        for component in self.components {
            do_write(&mut target_file, component);
        }
        for (name, test_case) in self.test_cases {
            let src_data_path = test_case.data_path.unwrap();
            let target_data_path =
                target_dir.join("data").join(src_data_path.strip_prefix(SRC_DIR).unwrap());
            do_copy(&src_data_path, &target_data_path);

            let rust_type = to_rust_type(self.ssz_type, &name);
            let project_path = target_data_path.strip_prefix("..").unwrap();
            let target_data_path = project_path.display();
            match test_case.format {
                Format::Valid => {
                    let value = to_rust_value(&name, &rust_type, test_case.value.unwrap());
                    let root = test_case.root.unwrap();
                    let name = name.to_case(Case::Snake);
                    let source = format!(
                        r#"
                #[test]
                fn test_{ssz_type}_{name}() {{
                    let value = {value};
                    let encoding = serialize(&value);
                    let expected_encoding = read_ssz_snappy_from_test_data("{target_data_path}");
                    assert_eq!(encoding, expected_encoding);

                    let recovered_value: {rust_type} = deserialize(&expected_encoding);
                    assert_eq!(recovered_value, value);

                    let root = hash_tree_root(&value);
                    let expected_root = root_from_hex("{root}");
                    assert_eq!(root, expected_root);
                }}
                "#
                    );
                    do_write(&mut target_file, source);
                }
                Format::Invalid => {
                    let name = name.to_case(Case::Snake);
                    let source = format!(
                        r#"
                #[test]
                #[should_panic]
                fn test_{ssz_type}_{name}() {{
                    let encoding = read_ssz_snappy_from_test_data("{target_data_path}");

                    deserialize::<{rust_type}>(&encoding);
                }}
                "#
                    );
                    do_write(&mut target_file, source);
                }
            }
        }
    }
}

fn generate_for(ssz_type: SszType) {
    let fmt = Format::Valid;
    let mut generator = Generator::new(ssz_type);
    let test_suite_path = PathBuf::from(SRC_DIR).join(ssz_type.to_string()).join(fmt.to_string());
    for test_case in fs::read_dir(test_suite_path).unwrap() {
        match test_case {
            Ok(path) => generator.load_test_case(fmt, path),
            Err(err) => panic!("{err}"),
        };
    }

    let fmt = Format::Invalid;
    let test_suite_path = PathBuf::from(SRC_DIR).join(ssz_type.to_string()).join(fmt.to_string());
    for test_case in fs::read_dir(test_suite_path).unwrap() {
        match test_case {
            Ok(path) => generator.load_test_case(fmt, path),
            Err(err) => panic!("{err}"),
        };
    }
    generator.execute();
}

fn main() {
    let current_dir = env::current_dir().unwrap();
    let current_dir = current_dir.file_name().unwrap();
    if !to_string(current_dir).contains("ssz-rs-test-gen") {
        panic!("please call this utility from the `ssz-rs-test-gen` package");
    }

    if let Some(ssz_type) = env::args().nth(1) {
        let ssz_type = SszType::from(ssz_type.as_ref());
        generate_for(ssz_type);
    } else {
        panic!("please supply a SSZ type from the spec tests to proceed")
    }
}
