extern crate rand;
use rand::thread_rng;
use std::io::Write;
use std::time::Instant;

extern crate curve25519_dalek;
use curve25519_dalek::scalar::Scalar;

extern crate merlin;
use merlin::Transcript;

extern crate bulletproofs;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

use std::fs::OpenOptions;

fn write_results_to_csv(
    results: &[(usize, f64, f64, usize, bool)],
    filename: &str,
) -> std::io::Result<()> {
    // Open file in append mode, create if it doesn't exist
    let file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(filename)?;
    
    let mut writer = std::io::BufWriter::new(file);
    
    // Check if file is empty (new file)
    let metadata = std::fs::metadata(filename)?;
    if metadata.len() == 0 {
        // Write header only for new files
        writeln!(
            writer,
            "Number of proofs,Generation time (s),Verification time (s),Proof size (bytes),Verified"
        )?;
    }

    // Write data rows
    for (num_proofs, gen_time, verify_time, proof_size, verified) in results {
        writeln!(
            writer,
            "{},{},{},{},{}",
            num_proofs, gen_time, verify_time, proof_size, verified
        )?;
    }

    // Ensure all data is written
    writer.flush()?;

    Ok(())
}

fn main() {
    for _ in 0..10 {
        run_bulletproofs(7);
    }
}

fn run_bulletproofs(max_power: u32) {
    std::env::set_var("RUST_BACKTRACE", "1");

    let mut results = vec![];

    // Generate the generators once with max capacity
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(64, 2usize.pow(max_power));

    // Only iterate over powers of 2 up to max_num_proofs
    for power in 0..=max_power {
        let num_proofs = 2usize.pow(power);

        println!(
            "Attempting to generate proof for batch size: {}",
            num_proofs
        );

        // Secret values and blinding factors
        let secrets: Vec<u64> = (0..num_proofs)
            .map(|_| Scalar::random(&mut thread_rng()).to_bytes()[0] as u64)
            .collect();
        let blindings: Vec<Scalar> = (0..num_proofs)
            .map(|_| Scalar::random(&mut thread_rng()))
            .collect();

        println!(
            "Generated {} secrets and {} blindings",
            secrets.len(),
            blindings.len()
        );

        let start_gen = Instant::now();
        let mut prover_transcript = Transcript::new(b"doctest example");

        match RangeProof::prove_multiple(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            &secrets,
            &blindings,
            32,
        ) {
            Ok((proof, commitments)) => {
                let gen_duration = start_gen.elapsed();
                let proof_size = proof.to_bytes().len();

                let start_verify = Instant::now();
                let mut verifier_transcript = Transcript::new(b"doctest example");
                let verification_result = proof.verify_multiple(
                    &bp_gens,
                    &pc_gens,
                    &mut verifier_transcript,
                    &commitments,
                    32,
                );

                let verify_duration = start_verify.elapsed();

                results.push((
                    num_proofs,
                    gen_duration.as_secs_f64(),
                    verify_duration.as_secs_f64(),
                    proof_size,
                    verification_result.is_ok(),
                ));

                println!(
                    "Successfully generated and verified proof for batch size: {}",
                    num_proofs
                );
            }
            Err(e) => {
                println!(
                    "Error generating proof for batch size {}: {:?}",
                    num_proofs, e
                );
                results.push((num_proofs, 0.0, 0.0, 0, false));
            }
        }
    }

    // Print the results to console
    println!("\nFinal Results:");
    println!("Number of proofs | Gen time (s) | Verify time (s) | Proof size (bytes) | Verified");
    println!("-----------------+-------------+----------------+-------------------+----------");
    for (num_proofs, gen_time, verify_time, proof_size, verified) in &results {
        println!(
            "{:<17} | {:<12.6} | {:<14.6} | {:<18} | {}",
            num_proofs, gen_time, verify_time, proof_size, verified
        );
    }

    // Write results to CSV file
    match write_results_to_csv(&results, "bulletproof_results.csv") {
        Ok(_) => println!("\nResults successfully written to bulletproof_results.csv"),
        Err(e) => println!("\nError writing to CSV file: {}", e),
    }
}
