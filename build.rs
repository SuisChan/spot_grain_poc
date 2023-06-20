use std::io::Result;

fn main() -> Result<()> {
    let root = std::env::current_dir()?.join("proto");

    prost_build::compile_protos(
        &[
            root.join("kex.proto"),
            root.join("auth.proto"),
        ],
        &[root],
    )?;

    Ok(())
}
