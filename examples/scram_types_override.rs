use scram_rs::{ScramType, ScramTypes, SCRAM_TYPE_256, SCRAM_TYPE_256_PLUS};

pub const MY_SCRAM_TYPES: &'static ScramTypes = 
    &ScramTypes::new(
        &[
            SCRAM_TYPE_256,
            SCRAM_TYPE_256_PLUS
        ]
    );

pub fn main()
{
    println!("{}", MY_SCRAM_TYPES.adrvertise(", "));
}