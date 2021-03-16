pub mod scram;
pub mod scram_cb;
pub mod scram_auth;
pub mod scram_hashing;
pub mod scram_common;
pub mod scram_error;

//@ see other realizations:
// https://doxygen.postgresql.org/auth-scram_8c_source.html
//https://github.com/tomprogrammer/scram/blob/ecb790c7d093c3704451a5238173c6bba794f1a5/src/server.rs
//https://gitlab.com/lumi/sasl-rs/-/blob/master/src/client/mechanisms/scram.rs

