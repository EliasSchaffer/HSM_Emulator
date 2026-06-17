use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use cryptoki_sys::{CK_RV, CK_FUNCTION_LIST, CK_NOTIFY, CK_SESSION_HANDLE, CK_FLAGS, CK_SLOT_ID, CK_VOID_PTR, CK_UTF8CHAR_PTR, CK_MECHANISM, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_USER_TYPE};
use std::ptr;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};
use bincode;

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmRequest {
    OpenSession,
    CloseSession { session_id: u64 },
    Sign { session_id: u64, data: Vec<u8> },
    
}

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmResponse {
    SessionOpened { session_id: u64 },
    SessionClosed,
    SignResult { signature: Vec<u8> },
    Error(String),
}


static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: cryptoki_sys::CK_VERSION { major: 2, minor: 40 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: None,
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: None,
    C_GetSlotInfo: None,
    C_GetTokenInfo: None,
    C_GetMechanismList: None,
    C_GetMechanismInfo: None,
    C_InitToken: None,
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: None,
    C_CloseAllSessions: Some(C_CloseSession),
    C_GetSessionInfo: None,
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: None,
    C_CopyObject: None,
    C_DestroyObject: None,
    C_GetObjectSize: None,
    C_GetAttributeValue: None,
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: None,
    C_Encrypt: None,
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: None,
    C_Decrypt: None,
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: None,
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: None,
    C_SignFinal: None,
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None,
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: None,
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: None,
    C_GenerateRandom: None,
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

static SERVER_CONNECTION: Mutex<Option<TcpStream>> = Mutex::new(None);


fn send_request(stream: &mut TcpStream, req: &HsmRequest) -> Result<HsmResponse, Box<dyn std::error::Error>> {    //serialize Request
    let encode: Vec<u8> = bincode::serialize(&req)?;
    let encoded_len = encode.len() as u32;
    stream.write_all(&encoded_len.to_be_bytes())?;
    stream.write_all(&encode)?;
    stream.flush()?;

    let mut len_bytes = [0u8;4];
    stream.read_exact(&mut len_bytes)?;
    let res_len = u32::from_be_bytes(len_bytes) as usize;

    let mut res_bytes = vec![0u8; res_len];
    stream.read_exact(&mut res_bytes)?;

    let response: HsmResponse = bincode::deserialize(&res_bytes)?;
    Ok(response)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(_pInitArgs: CK_VOID_PTR) -> CK_RV {
    let mut conn_guard = SERVER_CONNECTION.lock().unwrap();

    if conn_guard.is_none() {
        match TcpStream::connect("127.0.0.1:8888") {
            Ok(stream) => {
                *conn_guard = Some(stream);
                0
            }
            Err(e) => {
                eprintln!("Network Error: {}", e);
                0x00000006
            }
        }
    }else {
        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(_pReserved: CK_VOID_PTR) -> CK_RV {
    let mut conn_guard = SERVER_CONNECTION.lock().unwrap();
    *conn_guard = None;
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_OpenSession(
    _slotID: CK_SLOT_ID,
    _flags: CK_FLAGS,
    _pApplication: CK_VOID_PTR,
    _Notify: CK_NOTIFY,
    phSession: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    if phSession.is_null() {
        return 0x00000007; // CKR_ARGUMENTS_BAD
    }
    let req = HsmRequest::OpenSession {};

    let mut conn_guard = SERVER_CONNECTION.lock().unwrap();

    if let Some(ref mut stream) = *conn_guard {
        // 1. Führe den Request aus und fange das Result ab
        match send_request(stream, &req) {
            Ok(HsmResponse::SessionOpened { session_id}) => {

                *phSession = session_id as CK_SESSION_HANDLE;

                println!("Request successfull, Session set.");
            }
            Ok(HsmResponse::Error(err_msg)) => {
                eprintln!("HSM Error: {}", err_msg);
                return 0x00000006;
            }
            Ok(_) => {
                eprintln!("Unexepected Response from HSM:");
                return 0x00000006;
            }
            Err(e) => {
                eprintln!("Network Error: {:?}", e);
                return 0x00000006;
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(session: CK_SESSION_HANDLE) -> CK_RV {



    let session_id = session as u64;
    let req = HsmRequest::CloseSession { session_id};

    let mut conn_guard = SERVER_CONNECTION.lock().unwrap();
    if let Some(ref mut stream) = *conn_guard {
        match send_request(stream, &req) {
            Ok(HsmResponse::SessionClosed) => {
                println!("Session closed!");
                0
            }
            _ => {
                eprintln!("Unexpected Response from HSM:");
                0x00000006
            }
        }
    } else {
        eprintln!("Fehler: No active Server Connection found!");
            0x00000003
    }
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    if ppFunctionList.is_null() {
        return 0x00000007;
    }
    *ppFunctionList = &FUNCTION_LIST as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST;
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    _session: CK_SESSION_HANDLE,
    _userType: CK_USER_TYPE,
    _pPin: CK_BYTE_PTR,
    _ulPinLen: CK_ULONG
) -> CK_RV {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Logout(_session: CK_SESSION_HANDLE) -> CK_RV {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GenerateKeyPair(
    _session: CK_SESSION_HANDLE,
    _pMechanism: *mut CK_MECHANISM,
    _pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
    _ulPublicKeyAttributeCount: CK_ULONG,
    _pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
    _ulPrivateKeyAttributeCount: CK_ULONG,
    _phPublicKey: *mut CK_OBJECT_HANDLE,
    _phPrivateKey: *mut CK_OBJECT_HANDLE
) -> CK_RV {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsInit(
    _session: CK_SESSION_HANDLE,
    _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG
) -> CK_RV {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjects(
    _session: CK_SESSION_HANDLE,
    _phObject: *mut CK_OBJECT_HANDLE,
    _ulMaxObjectCount: CK_ULONG,
    _pulObjectCount: *mut CK_ULONG
) -> CK_RV {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsFinal(_session: CK_SESSION_HANDLE) -> CK_RV {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignInit(
    _session: CK_SESSION_HANDLE,
    _pMechanism: *mut CK_MECHANISM,
    _hKey: CK_OBJECT_HANDLE
) -> CK_RV {
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Sign(
    session: CK_SESSION_HANDLE,
    _pData: CK_BYTE_PTR,
    _ulDataLen: CK_ULONG,
    _pSignature: CK_BYTE_PTR,
    _pulSignatureLen: *mut CK_ULONG
) -> CK_RV {
    if _pData.is_null() {
        return 0x00000007;
    }

    let data_slice = std::slice::from_raw_parts(_pData, _ulDataLen as usize);
    let data_vec = Vec::from(data_slice);

    let session_id = session as u64;
    let req = HsmRequest::Sign { session_id, data: data_vec };

    let mut conn_guard = SERVER_CONNECTION.lock().unwrap();
    if let Some(ref mut stream) = *conn_guard {

        match send_request(stream, &req) {
            Ok(HsmResponse::SignResult { signature }) => {
                println!("Signature received from HSM!");
                if _pSignature.is_null() {
                    *_pulSignatureLen = signature.len() as CK_ULONG;
                    return 0;
                }

                if (*_pulSignatureLen as usize) < signature.len() {
                    *_pulSignatureLen = signature.len() as CK_ULONG;
                     return 0x00000150
                }

                std::ptr::copy_nonoverlapping(signature.as_ptr(), _pSignature, signature.len());
                *_pulSignatureLen = signature.len() as CK_ULONG;

                0
            }
            Ok(HsmResponse::Error(err)) => {
                eprintln!("Server Error: {}", err);
                0x00000006
            }
            Err(e) => {
                eprintln!("Network Error: {}", e);
                0x00000006
            }
            _ => 0x00000006,
        }

    } else {
        eprintln!("Fehler: No active Server Connection found!");
        0x00000003
    }
}


