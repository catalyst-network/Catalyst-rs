use crate::errors;
use crate::error_codes;
use libc::c_int;

pub trait ResultEx{
    fn ffi_return_code(self) -> c_int;
}

impl ResultEx for Result<(),failure::Error> {
    fn ffi_return_code(self) -> c_int{
        match self{
            Err(err) => {
                let error_code = error_codes::get_error_code(&err);
                errors::update_last_error(err);
                return error_code;
            }
            Ok(_t) => {
                return 0
            }
        }; 
    } 
}  