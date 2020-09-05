use std::{ env, io::Write, time::Instant };
use distaff::{ self, StarkProof };

mod examples;
use examples::{ Example };
use std::fs::File;

fn main() {

    // configure logging
    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(log::LevelFilter::Debug).init();

    // determine the example to run based on command-line inputs
    let ex: Example;
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        ex = examples::fibonacci::get_example(&args);
    }
    else {
        ex = match args[1].as_str() {
            "collatz"       => examples::collatz::get_example(&args[1..]),
            "comparison"    => examples::comparison::get_example(&args[1..]),
            "conditional"   => examples::conditional::get_example(&args[1..]),
            "fibonacci"     => examples::fibonacci::get_example(&args[1..]),
            "merkle"        => examples::merkle::get_example(&args[1..]),
            "rangecheck"    => examples::range::get_example(&args[1..]),
            _ => panic!("Could not find example program for '{}'", args[1])
        }
    }
    let Example { program, inputs, num_outputs, options, expected_result } = ex;
    println!("--------------------------------");

    // execute the program and generate the proof of execution
    let now = Instant::now();
    let (outputs, proof) = distaff::execute(&program, &inputs, num_outputs, &options);
    println!("--------------------------------");
    println!("Executed program with hash {} in {} ms", 
        hex::encode(program.hash()),
        now.elapsed().as_millis());
    println!("Program output: {:?}", outputs);
    assert_eq!(expected_result, outputs, "Program result was computed incorrectly");

    // serialize the proof to see how big it is
    let proof_bytes = bincode::serialize(&proof).unwrap();
    println!("Execution proof size: {} KB", proof_bytes.len() / 1024);
    println!("Execution proof security: {} bits", options.security_level(true));
    println!("--------------------------------");

	let s_program_hash = bincode::serialize(&program.hash()).unwrap();
	let s_public_input = bincode::serialize(&inputs.get_public_inputs()).unwrap();
	let s_outputs = bincode::serialize(&outputs).unwrap();
	let s_proof= bincode::serialize(&proof).unwrap();

	let d_program_hash : [u8; 32]= bincode::deserialize(&s_program_hash).unwrap();
	let d_public_input :  Vec<u128>= bincode::deserialize(&s_public_input).unwrap();
	let d_outputs : Vec<u128>= bincode::deserialize(&s_outputs).unwrap();
	let d_proof : StarkProof = bincode::deserialize(&s_proof).unwrap();

	let path_program_hash: &str = "s_program_hash";
	let mut output: File = File::create(path_program_hash).unwrap();
	output.write(&s_program_hash);

	let path_public_input: &str = "s_public_input";
	let mut output: File = File::create(path_public_input).unwrap();
	output.write(&s_public_input);

	let path_outputs: &str = "s_output";
	let mut output: File = File::create(path_outputs).unwrap();
	output.write(&s_outputs);

	let path_proof: &str = "s_proof";
	let mut output: File = File::create(path_proof).unwrap();
	output.write(&s_proof);

	let _proof = bincode::deserialize::<StarkProof>(&proof_bytes).unwrap();
	let now = Instant::now();

	match distaff::verify(&d_program_hash, &d_public_input, &d_outputs, &d_proof) {
		Ok(_) => println!("Execution verified in {} ms", now.elapsed().as_millis()),
		Err(msg) => println!("Failed to verify execution: {}", msg)
	}

}