fn main() {
    let production = std::env::args().any(|a| a == "--production");
    println!("{}", rand_prover_wasm_spike::run(production, true));
}
