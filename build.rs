fn main() {
    capnpc::CompilerCommand::new()
        .src_prefix("schema")
        .file("schema/rap.capnp")
        .run()
        .expect("compiling schema");
}
