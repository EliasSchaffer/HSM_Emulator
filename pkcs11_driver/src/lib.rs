use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use cryptoki_sys::{CK_RV, CK_FUNCTION_LIST, CK_NOTIFY, CK_SESSION_HANDLE, CK_FLAGS, CK_SLOT_ID, CK_VOID_PTR, CK_UTF8CHAR_PTR, CK_MECHANISM, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_USER_TYPE, CK_INFO, CK_SLOT_INFO, CK_TOKEN_INFO};
use std::ptr;
use std::sync::{LazyLock, Mutex};
use serde::{Deserialize, Serialize};
use bincode;

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmRequest {
    OpenSession,
    CloseSession { session_id: u64 },
    Sign { session_id: u64, key_id: String, data: Vec<u8> },
    GenerateKey { key_id: String, key_type: String },
    Error(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum HsmResponse {
    SessionOpened { session_id: u64 },
    SessionClosed,
    SignResult { signature: Vec<u8> },
    KeyGenerated,
    Error(String),
}

static SESSION_KEYS: LazyLock<Mutex<HashMap<u64, u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: cryptoki_sys::CK_VERSION { major: 2, minor: 40 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
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
static FIND_STATE_RETURNED: Mutex<bool> = Mutex::new(false);


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

    let mut key_id = String::new();
    let attributes = unsafe {
        std::slice::from_raw_parts(_pPublicKeyTemplate, _ulPublicKeyAttributeCount as usize)
    };

    for attr in attributes {
        if attr.type_ == cryptoki_sys::CKA_ID {
            let value_slice = unsafe {
                std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize)
            };
            key_id = String::from_utf8_lossy(value_slice).into_owned();
            break;
        }
    }

    if key_id.is_empty() {
        key_id = "default_key_id".to_string();
    }

    let mech_type = unsafe { (*_pMechanism).mechanism };
    let key_type = match mech_type {
        cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN => "RSA-2048",
        cryptoki_sys::CKM_EC_KEY_PAIR_GEN => "ECDSA",
        _ => "Ed25519",
    };


    let req = HsmRequest::GenerateKey {
        key_id: key_id.clone(),
        key_type: key_type.to_string()
    };

    let mut conn_guard = SERVER_CONNECTION.lock().unwrap();

    if let Some(ref mut stream) = *conn_guard {
        match send_request(stream, &req) {
            Ok(HsmResponse::KeyGenerated) => {
                println!("Schlüssel erfolgreich im HSM generiert!");

                let numeric_handle = key_id.parse::<u64>().unwrap_or(1001);

                if !_phPublicKey.is_null() {
                    *_phPublicKey = numeric_handle as CK_OBJECT_HANDLE;
                }
                if !_phPrivateKey.is_null() {
                    *_phPrivateKey = numeric_handle as CK_OBJECT_HANDLE;
                }
            }
            Ok(HsmResponse::Error(err_msg)) => {
                eprintln!("HSM Error: {}", err_msg);
                return 0x00000006;
            }
            Ok(other) => {
                eprintln!("Unerwartete Antwort vom HSM: {:?}", other);
                return 0x00000006;
            }
            Err(e) => {
                eprintln!("Netzwerkfehler: {:?}", e);
                return 0x00000006;
            }
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsInit(
    _session: CK_SESSION_HANDLE,
    _pTemplate: CK_ATTRIBUTE_PTR,
    _ulCount: CK_ULONG
) -> CK_RV {
    let mut returned = FIND_STATE_RETURNED.lock().unwrap();
    *returned = false;
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjects(
    _session: CK_SESSION_HANDLE,
    _phObject: *mut CK_OBJECT_HANDLE,
    _ulMaxObjectCount: CK_ULONG,
    _pulObjectCount: *mut CK_ULONG
) -> CK_RV {
    if _phObject.is_null() {
        return 0x00000007;
    }

    let mut returned = FIND_STATE_RETURNED.lock().unwrap();

    unsafe {
        if *returned && _ulMaxObjectCount > 0 {
            *_phObject = 10 as cryptoki_sys::CK_OBJECT_HANDLE;
            *_pulObjectCount = 1;
            *returned = true;
        }else {
            *_pulObjectCount = 0;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsFinal(_session: CK_SESSION_HANDLE) -> CK_RV {

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignInit(
    session: CK_SESSION_HANDLE,
    _pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE
) -> CK_RV {
    let session_id = session as u64;
    let key_handle = hKey as u64;

    let mut keys_guard = SESSION_KEYS.lock().unwrap();
    keys_guard.insert(session_id, key_handle);

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

    let session_id = session as u64;

    let key_handle = {
        let keys_guard = SESSION_KEYS.lock().unwrap();
        match keys_guard.get(&session_id) {
            Some(handle) => *handle,
            None => return 0x00000006,
        }
    };

    let key_id = key_handle.to_string();


    let data_slice = std::slice::from_raw_parts(_pData, _ulDataLen as usize);
    let data_vec = Vec::from(data_slice);

    let session_id = session as u64;
    let req = HsmRequest::Sign { session_id, key_id, data: data_vec };

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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotList(
    tokenPresent: cryptoki_sys::CK_BBOOL,
    pSlotList: *mut CK_SLOT_ID,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    if pulCount.is_null() {
        return 0x00000007;
    }

    let fake_slots = [1u64];

    if pSlotList.is_null() {
        *pulCount = fake_slots.len() as CK_ULONG;
        return 0;
    }

    if (*pulCount as usize) < fake_slots.len() {
        *pulCount = fake_slots.len() as CK_ULONG;
        return 0x00000150; // CKR_BUFFER_TOO_SMALL
    }

    std::ptr::copy_nonoverlapping(fake_slots.as_ptr() as *const CK_SLOT_ID, pSlotList, fake_slots.len());
    *pulCount = fake_slots.len() as CK_ULONG;

    0
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetInfo(pInfo: *mut CK_INFO) -> CK_RV {
    if pInfo.is_null() {
        return 0x00000007;
    }

    unsafe {
        (*pInfo).cryptokiVersion = cryptoki_sys::CK_VERSION { major: 2, minor: 40};

        let manufacturer_id = "PKCS#11 Driver";
        let library_description = "PKCS#11 Driver";

        std::ptr::copy_nonoverlapping(manufacturer_id.as_ptr(), (*pInfo).manufacturerID.as_mut_ptr(), manufacturer_id.len());
        std::ptr::copy_nonoverlapping(library_description.as_ptr(), (*pInfo).libraryDescription.as_mut_ptr(), library_description.len());

        (*pInfo).flags = 0;
        (*pInfo).libraryVersion = cryptoki_sys::CK_VERSION { major: 1, minor: 0};
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_SLOT_INFO) -> CK_RV {
    if pInfo.is_null() {
        return 0x00000007;
    }

    if slotID != 1 {
        return 0x00000003;
    }

    unsafe {
        let desc = b"PKCS#11 Slot";
        let manuf = b"PKCS#11 Driver";

        std::ptr::copy_nonoverlapping(desc.as_ptr(), (*pInfo).slotDescription.as_mut_ptr(), desc.len());
        std::ptr::copy_nonoverlapping(manuf.as_ptr(), (*pInfo).manufacturerID.as_mut_ptr(), manuf.len());

        (*pInfo).flags = 0x00000001 | 0x00000002;
        (*pInfo).hardwareVersion = cryptoki_sys::CK_VERSION { major: 1, minor: 0 };
        (*pInfo).firmwareVersion = cryptoki_sys::CK_VERSION { major: 1, minor: 0 };

    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_TOKEN_INFO) -> CK_RV {
    if pInfo.is_null() {
        return 0x00000007;
    }

    if slotID != 1 {
        return 0x00000003;
    }

    unsafe {
        let label = b"PKCS#11 Token";
        let manuf = b"PKCS#11 Driver";
        let model = b"PKCS#11 Model";
        let serial = b"PKCS#11 Serial";

        std::ptr::copy_nonoverlapping(label.as_ptr(), (*pInfo).label.as_mut_ptr() as *mut u8, 32);
        std::ptr::copy_nonoverlapping(manuf.as_ptr(), (*pInfo).manufacturerID.as_mut_ptr() as *mut u8, 32);
        std::ptr::copy_nonoverlapping(model.as_ptr(), (*pInfo).model.as_mut_ptr() as *mut u8, 16);
        std::ptr::copy_nonoverlapping(serial.as_ptr(), (*pInfo).serialNumber.as_mut_ptr() as *mut u8, 16);

        (*pInfo).flags = 0x00000400 | 0x00000008 | 0x00000100;
        (*pInfo).ulMaxSessionCount = 100;
        (*pInfo).ulSessionCount = 0;
        (*pInfo).ulMaxRwSessionCount = 100;
        (*pInfo).ulRwSessionCount = 0;
        (*pInfo).ulMaxPinLen = 8;
        (*pInfo).ulMinPinLen = 4;
        (*pInfo).ulTotalPublicMemory = 1024 * 1024;
        (*pInfo).ulFreePublicMemory = 1024 * 1024;
        (*pInfo).ulTotalPrivateMemory = 1024 * 1024;
        (*pInfo).ulFreePrivateMemory = 1024 * 1024;
        (*pInfo).hardwareVersion = cryptoki_sys::CK_VERSION { major: 1, minor: 0 };
        (*pInfo).firmwareVersion = cryptoki_sys::CK_VERSION { major: 1, minor: 0 };
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismList(
    slotID: cryptoki_sys::CK_SLOT_ID,
    pMechanismList: cryptoki_sys::CK_MECHANISM_TYPE_PTR,
    pulCount: cryptoki_sys::CK_ULONG_PTR
) -> cryptoki_sys::CK_RV {
    if pulCount.is_null() {
        return 0x00000007;
    }

    if slotID != 1 {
        return 0x00000003;
    }

    let supported_mechs = [
        cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN,
        cryptoki_sys::CKM_RSA_PKCS,
        cryptoki_sys::CKM_EC_KEY_PAIR_GEN,
    ];

    unsafe {
        if pMechanismList.is_null() {
            *pulCount = supported_mechs.len() as cryptoki_sys::CK_ULONG;
            return 0;
        }

        if *pulCount < supported_mechs.len() as cryptoki_sys::CK_ULONG {
            *pulCount = supported_mechs.len() as cryptoki_sys::CK_ULONG;
            return 0x00000150; // CKR_BUFFER_TOO_SMALL
        }

        std::ptr::copy_nonoverlapping(
            supported_mechs.as_ptr(),
            pMechanismList,
            supported_mechs.len()
        );
        *pulCount = supported_mechs.len() as cryptoki_sys::CK_ULONG;
    }

    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: cryptoki_sys::CK_SLOT_ID,
    type_: cryptoki_sys::CK_MECHANISM_TYPE,
    pInfo: cryptoki_sys::CK_MECHANISM_INFO_PTR
) -> cryptoki_sys::CK_RV {
    if pInfo.is_null() { return 0x00000007; }
    if slotID != 1 { return 0x00000003; }

    unsafe {
        match type_ {
            cryptoki_sys::CKM_RSA_PKCS_KEY_PAIR_GEN => {
                (*pInfo).ulMinKeySize = 1024;
                (*pInfo).ulMaxKeySize = 4096;
                (*pInfo).flags = 0x00008000;
            }
            cryptoki_sys::CKM_RSA_PKCS => {
                (*pInfo).ulMinKeySize = 1024;
                (*pInfo).ulMaxKeySize = 4096;
                (*pInfo).flags = 0x00000800;
            }
            cryptoki_sys::CKM_EC_KEY_PAIR_GEN => {
                (*pInfo).ulMinKeySize = 256;
                (*pInfo).ulMaxKeySize = 521;
                (*pInfo).flags = 0x00008000;
            }
            _ => {
                return 0x00000160;
            }
        }
    }
    0
}


