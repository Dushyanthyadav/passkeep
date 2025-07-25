use argon2::{password_hash::SaltString, Algorithm, Argon2, ParamsBuilder, PasswordHasher, Version};


//This function gives the returns the key of the password from the user 

pub fn argon2_encode(m_cost: u32, t_cost: u32, p_cost: u32, output_len: usize, version: Version, algorithm: Algorithm, password: &String, salt: &[u8]) -> Vec<u8> {


    //creation of parameters
    let mut parameters = ParamsBuilder::new();
    parameters.m_cost(m_cost);
    parameters.t_cost(t_cost);
    parameters.p_cost(p_cost);
    parameters.output_len(output_len);

    let my_params = parameters.build().unwrap();

    let argon = Argon2::new(algorithm, version, my_params);
    //hash generation
    let mut hash = vec![0u8; output_len];
    

    argon.hash_password_into(&password.as_bytes(), &salt, &mut hash).unwrap();
    
    hash
    
}