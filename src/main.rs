use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use grain128::Grain128;
use prost::Message;
use sha1::{Digest, Sha1};

use crate::spotify::{ApResponseMessage, ClientHello};

// include protobuf defs
pub mod spotify {
    include!(concat!(env!("OUT_DIR"), "/spotify.rs"));
}

pub type Aes128CbcEncryptor = cbc::Encryptor<aes::Aes128>;
pub type Aes128CbcDecryptor = cbc::Decryptor<aes::Aes128>;

fn main() {
    // for example, I will use ready-made data, as it's allow to show the very essence and how it works

    let client_hello_msg = hex::decode("00040000017f520f5002a00100f00106c002c1fda89b03a00100f00100c00200920367526552608f0f55bc2c145c9a8e5bf9b461e6369b8719dbc29e349942b6e16ab16f212b3369fdad0f34e6f57e352b425798f7638d486ec8cde03ea25b3a2e16f9bf25610f64a091fa264be1b6daeca57cf3b5e04585b21db14384270498bf94a74398ed14a00101e203104e6d66ccee731233bda9522b01ffb05bb204d3017ad8f26c668207bbe7541867de62a7b8bd11e96865e5e6e39e79904ddbda5d7c99eb302a7a417e57c11e0baeb4f30503e0ea3259a852b2cbdebfc349ecb914085204b1efeffda6615d5a54890b14026c653f201af8554a4f9c72315e420772a97ec0f1539b989f3a17686f48b0c59aa36fe773bbe54518349c7b4fa5e2edd398c1088f202c4d3f5ac2f7bc869e8e7f43c998016c4a1218a05fa44277c9b132e3aff73dcbca79c0d7d9dd955b43d3f7bf1e6104bd378641826d0a3339116fe154e1cc42e26bcd39d3fa4b4190fee22eae79de0d82050808011a002a020800").unwrap();
    let ap_response_msg = hex::decode("0000026552de0452ec0252e9025260a96f988bab77a3238f3ba5d40b7f7ca2b552cf71d6d8e148d89dad0e4ba8fe6828cfa2e99c6ca7b76502357accc476cd4df627dc9f862242ef5af2acb4cb7384512cbde2f2bbf1c18419666f61e1b094236c7a98cd8719fe93ed5d423de2098ea00100f20180022a8ad182300a2ec20c24a9aba55b5b598991365667b19b6c5b1eee1032bc49b5c2a8e02fd51c74d358b97111071a2f0e18da64bff775bb6565f2d9dd4978530c249cf8104406e0d234ce1d46d881eb619fb6a3d6a16399da798a9694d8f703c5b65ac85c4b15659dfd168d393a13830137a6d6016f72cdae28687736aa00cdd6b908f490062a244e3892a4dddaee5d0113c2d678bffd8e40f293c62727edd056eedb2bb0ca3a9f37b0c3bf8e219d0423dc97a37cfcc64a6a34c247519d69dfb9a375b37341c854303a9a6a7672205675cc4df93c3421ad378dfcb7d75aa41adf164a8db5397dca019b731793976941c363f21cfe94dc40ecefecf21dfc8a9c3ea201145212521090dcf56fc67a5cb7e1acffabf4949f04f2011c521a521095f4103cdc076ae079e8548d7008fed8a0010ef001dced03c20202520092031095f4103cdc076ae079e8548d7008fed8e2039d017c0b3a5c8422b01193b8106b9406fc71fb6b3776c7ee5773ed036781a26b511e768b7bfbae2b0c41e41cac7822a8e91e132094da0eeb4dfbeeb47c911fcdaf96592a9107569d483abaf4b2dc9d9cfab0bc8e8bcb7ad8c6688d43f9ac10a94269d3d3702971b8632bad16074ab202fa6e9085390a5e0073eb436c975315dabde9ad2d121ee67649938c51dd3e53d7ace35de6eebbe661a629cd3d7ce317").unwrap();

    // shows how the client implementation works
    let encrypted_key = client_side(&client_hello_msg, &ap_response_msg).unwrap();

    // from the server's perspective, here is how it can be verified
    server_side(&client_hello_msg, &ap_response_msg, &encrypted_key).unwrap();
}

fn client_side(client_hello: &[u8], ap_response: &[u8]) -> anyhow::Result<Vec<u8>> {
    println!("\nclient side:\n");

    // first, the client generates a `secret_key` which will be used in the process
    // let client_secret_key: [u8; 0x10] = rand::random() as an example, but in the example it is pre-generated
    let client_secret_key = hex::decode("61664c65ee991fa086c2dbdf89ab2288")?;

    // initialize Grain128 instance with client's secret key and encrypt an empty slice ([0u8; 0x10])
    // result will become a `client_nonce` which will be used in the `ClientHello` message
    let mut client_nonce = [0u8; 0x10];

    let mut gc = Grain128::keysetup(&client_secret_key, 128, 128);
    gc.ivsetup(&[0u8; 0x10]);
    gc.encrypt_bytes(&[0u8; 0x10], &mut client_nonce);

    // expected client nonce: [4e, 6d, 66, cc, ee, 73, 12, 33, bd, a9, 52, 2b, 01, ff, b0, 5b]
    println!("client_nonce: {client_nonce:02x?}");

    // for the test I make sure that it is the same as in the message
    let client_hello_pb = ClientHello::decode(&client_hello[6..])?;
    assert_eq!(client_hello_pb.client_nonce, client_nonce);

    // ...sends a `ClientHello` message and get `ApResponseMessage` in response
    let ap_response_pb = ApResponseMessage::decode(&ap_response[4..])?;

    // now we will create an `encrypted_key` that will be sent in `ClientResponseEncrypted`

    // make sha1 (client_hello || ap_response)
    let mut sha1 = Sha1::new();
    sha1.update(client_hello);
    sha1.update(ap_response);
    let message_digest = sha1.finalize();
    // expected message_digest: [1e, 4d, dc, 0b, 47, 99, fc, 66, 7e, 49, eb, 6f, 8e, 2a, ae, a0, 71, 86, 8e, 32]
    println!("message_digest: {message_digest:02x?}");

    // using the server data we get the AES key
    let kek = ap_response_pb
        .challenge
        .unwrap()
        .fingerprint_challenge
        .grain
        .unwrap()
        .kek;

    let mut aes_key = [0u8; 0x10];

    let mut gs = Grain128::keysetup(&kek, 128, 128);
    gs.ivsetup(&[0u8; 0x10]);
    //  use message_digest[..0x10]
    gs.encrypt_bytes(&message_digest[..0x10], &mut aes_key);

    // expected aes_key: [3e, 1c, b5, 5b, f5, 73, 0a, b4, e1, 7c, a7, 14, c9, 50, 8c, 38]
    println!("aes_key: {aes_key:02x?}");

    // now create an AES instance (CBC-128-NoPadding) and encrypt the client's `secret_key`
    let aes_iv = [0u8; 0x10];
    let cipher = Aes128CbcEncryptor::new_from_slices(&aes_key, &aes_iv)?;

    let mut encrypted_key = client_secret_key;
    cipher
        .encrypt_padded_mut::<NoPadding>(&mut encrypted_key, 0x10)
        .expect("encrypt_padded_mut");

    // use the encryped_key in the next (ClientResponseEncrypted) message to the server

    /* ClientResponseEncrypted {
        ...
        fingerprint_response {
          grain {
            encrypted_key: "................."
          }
        }
    } */

    // since `ClientResponseEncrypted` stores login and auth_data - I didn't include it in the code, only `encrypted_key`
    let expected_encrypted_key = hex::decode("2d0cf973d2235dc7010e07c640d28872")?;
    assert_eq!(expected_encrypted_key, encrypted_key);

    Ok(encrypted_key)
}

fn server_side(
    client_hello: &[u8],
    ap_response: &[u8],
    encrypted_key: &[u8],
) -> anyhow::Result<()> {
    println!("\nserver side:\n");

    // the server does almost the same

    // make sha1 (client_hello || ap_response)
    let mut sha1 = Sha1::new();
    sha1.update(client_hello);
    sha1.update(ap_response);
    let message_digest = sha1.finalize();

    // expected message_digest: [1e, 4d, dc, 0b, 47, 99, fc, 66, 7e, 49, eb, 6f, 8e, 2a, ae, a0, 71, 86, 8e, 32]
    println!("message_digest: {message_digest:02x?}");

    let ap_response_pb = ApResponseMessage::decode(&ap_response[4..])?;

    // using the server data we get the AES key
    let kek = ap_response_pb
        .challenge
        .unwrap()
        .fingerprint_challenge
        .grain
        .unwrap()
        .kek;

    let mut aes_key = [0u8; 0x10];

    let mut gs = Grain128::keysetup(&kek, 128, 128);
    gs.ivsetup(&[0u8; 0x10]);
    //  use message_digest[..0x10]
    gs.encrypt_bytes(&message_digest[..0x10], &mut aes_key);

    // expected aes_key: [3e, 1c, b5, 5b, f5, 73, 0a, b4, e1, 7c, a7, 14, c9, 50, 8c, 38]
    println!("aes_key: {aes_key:02x?}");

    // now create an AES instance (CBC-128-NoPadding) and decrypt the client's `secret_key`
    let aes_iv = [0u8; 0x10];

    // create decryptor
    let cipher = Aes128CbcDecryptor::new_from_slices(&aes_key, &aes_iv)?;

    // and decrypt `encrypted_key` from `ClientResponseEncrypted`
    let mut decrypted_client_secret_key = encrypted_key.to_owned();

    cipher
        .decrypt_padded_mut::<NoPadding>(&mut decrypted_client_secret_key)
        .expect("decrypt_padded_mut");

    // expected decrypted_client_secret_key: [61, 66, 4c, 65, ee, 99, 1f, a0, 86, c2, db, df, 89, ab, 22, 88]
    println!("decrypted_client_secret_key: {decrypted_client_secret_key:02x?}");

    // now that we have the client's `secret_key` we can verify the client with `Grain128` cipher
    let mut gc = Grain128::keysetup(&decrypted_client_secret_key, 128, 128);
    gc.ivsetup(&[0u8; 0x10]);

    // decrypt client nonce, and we should get an empty slice ([0u8; 0x10])
    let client_hello_pb = ClientHello::decode(&client_hello[6..])?;
    let client_nonce = client_hello_pb.client_nonce;
    let mut plaintext = client_nonce.clone();

    gc.decrypt_bytes(&client_nonce, &mut plaintext);

    assert_eq!(&plaintext, &[0u8; 0x10]);
    println!("plaintext: {plaintext:02x?}");

    Ok(())
}
