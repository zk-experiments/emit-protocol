#![allow(clippy::print_stdout)]
//! Writes the release catalog (`catalog.json`): this layer's identity, the toolchain pins, its
//! families with their roots and layouts, the pipelines and the deployment root, and the kernels
//! it folds with, so a consumer can check what a published release is before depending on it.
//!
//! cargo run --release -p emit-circuits --bin catalog -- <version> <resources.tar.gz sha256>

use emit_circuits::circuits::{DEPLOYMENT_ROOT, FAMILIES, LIBRARY, pipelines};
use emit_circuits::hex32;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (version, sha256) = (args.get(1).cloned(), args.get(2).cloned());
    let manifest: toml::Value = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/circuits/manifest.toml"
    )))
    .expect("manifest");
    let families: Vec<serde_json::Value> = FAMILIES
        .iter()
        .filter(|f| f.id.library == LIBRARY.name)
        .map(|f| {
            serde_json::json!({
                "id": format!("{}/{}/{}", f.id.library, f.id.layer, f.id.family),
                "root": hex32(&f.root),
                "members": f.members.iter().map(|(l, h)| serde_json::json!({"label": l, "vk_hash": hex32(h)})).collect::<Vec<_>>(),
                "record_fields": f.record_fields,
                "link_in": f.link_in.map(|l| serde_json::json!({"index": l.index, "link": l.link})),
                "link_out": f.link_out.map(|l| serde_json::json!({"index": l.index, "link": l.link})),
                "binds": f.binds.iter().map(|b| serde_json::json!({"slot": b.slot, "index": b.index})).collect::<Vec<_>>(),
                "public_from": f.public_from,
                "slots": f.slots,
            })
        })
        .collect();
    let pipeline = |p: &noir_zk_core::PipelineEntry| serde_json::json!({"name": p.name, "root": hex32(&p.root), "length": p.len(), "slots": p.slots});
    let kernels = &noir_zk_backend::kernels::FAMILY;
    let out = serde_json::json!({
        "library": LIBRARY.name,
        "version": version.unwrap_or_else(|| LIBRARY.version.to_string()),
        "noir": manifest["noir"].as_str(),
        "bb": manifest["bb"].as_str(),
        "resources_sha256": sha256,
        "families": families,
        "pipelines": [
            pipeline(&pipelines::identity_register::PIPELINE),
            pipeline(&pipelines::member_transfer::PIPELINE),
            pipeline(&pipelines::member_resolve::PIPELINE),
        ],
        "deployment_root": hex32(&DEPLOYMENT_ROOT),
        "kernels": {
            "library": kernels.id.library,
            "version": kernels.version,
            "family_root": hex32(&kernels.root),
        },
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("json"));
}
