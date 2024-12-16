use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use std::io;
use hex;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn decrypt_hex(encrypted_hex: &str, key: &[u8], iv: &[u8]) -> Result<u32, Box<dyn std::error::Error>> {
    let encrypted_bytes = hex::decode(encrypted_hex)?;
    let cipher = Aes128Cbc::new_from_slices(key, iv)?;
    let decrypted_bytes = cipher.decrypt_vec(&encrypted_bytes)?;
    let len = decrypted_bytes.len();
    if len < 4 {
        return Err("Decrypted data too short".into());
    }
    let result = u32::from_be_bytes(decrypted_bytes[len-4..].try_into()?);
    Ok(result)
}

fn get_decrypted_values() -> Vec<u32> {
    let key = b"amzpqwestwgckshy";
    let iv = b"vsjwpokqweqofbmy";

    let encrypted_values = vec![
"28ce5c78e2af45d7d9998993b52a815b", "c927a4a41a8f263a64727c4924db3b80",

"9b61a79e96b2900187109e7dc2a9b80a", "b1d4e8fb2b816f8b65dc6bdfda411dd6",

"fb25c9f8b411ad2f63c1e03edfbc72bf", "963eff5569548b3dbe2158522ae26722",

"f4f5ee5502dd8fb2561567f052693328", "d2c22194d9fb9acacd87e4127b7ad0f7",

"2a21a1486b6c9a36668f1425e90de7af", "e87d84083df0945a86374fdc5ec76224",

"2430e3ba14543ccb13ee315beb88e903", "6eee3efe14a46d4053b8d24bd29abd4b",

"60321b6ba267d8f6d05e98564dfd9545", "c8731ed736fb7911ac0b2804021a0f16",

"96f4d52c469abe8a8d278f0c4499a09a", "5e05380a70c9bebbe009a282b2a19657",

"c0e906fe203feca4e4b3c29439d54ee3", "e3511cd9a041b5e198468e37d1920262",

"cf400dbeedb9f6e6a55e39378a42c58c", "c9d75442e56447881203d1ff1e43fe39",

"b8a103723b5f30ddaf8d0b211a3ddace", "18a64d7de48e1f7a54804114408f0433",

"36bccf9492fd3a81dfaae522fd7f0ce9", "42fac0310bc93922b64be9e129306dc6",

"f9bf92fe541402ae6666cfc0ee5fabe8", "9616a3647f41cf7714d25c06be606f3f",

"237753d5c22b33272d26a602a617837f", "4f4658cef229f529b11907a5c0f86561",

"4ad7c97353e47e5cb4edea0ae21cd919", "986809a29c1e3097e97134f109c926c8",

"1998f05fb74c19b4a86ce11387fb34fa", "c77083aa3320196db463396465436c7f",

"832881da7c60f09c27c704063f285ada", "132bf4e3313629b29c7a751d16101fe2",

"4ad7c97353e47e5cb4edea0ae21cd919", "d2e8e62c7b540d9f49f4d1c96a2fc5d6",

"42fac0310bc93922b64be9e129306dc6", "f9bf92fe541402ae6666cfc0ee5fabe8",

"9616a3647f41cf7714d25c06be606f3f", "5e05380a70c9bebbe009a282b2a19657",

"f4f5ee5502dd8fb2561567f052693328", "d2c22194d9fb9acacd87e4127b7ad0f7",

"2a21a1486b6c9a36668f1425e90de7af", "e87d84083df0945a86374fdc5ec76224",

"2430e3ba14543ccb13ee315beb88e903", "4f4658cef229f529b11907a5c0f86561",

"4ad7c97353e47e5cb4edea0ae21cd919", "f4f5ee5502dd8fb2561567f052693328",

"d2c22194d9fb9acacd87e4127b7ad0f7", "2a21a1486b6c9a36668f1425e90de7af",

"e87d84083df0945a86374fdc5ec76224", "97d4ce5f709dcce0ff82c0961a4b21a7",

"23e540eaed50958109ab6432d84fdec1", "9f4d15414a9abf8d267efc4171030b7c",

"564e1237d943d1186dae088caf27643b", "d810bf1e82139012a42972ce8763de1b",

"c0e906fe203feca4e4b3c29439d54ee3", "e3511cd9a041b5e198468e37d1920262",

"cf400dbeedb9f6e6a55e39378a42c58c", "c9d75442e56447881203d1ff1e43fe39",

"f4f5ee5502dd8fb2561567f052693328", "d2c22194d9fb9acacd87e4127b7ad0f7",

"2a21a1486b6c9a36668f1425e90de7af", "e87d84083df0945a86374fdc5ec76224",

"2430e3ba14543ccb13ee315beb88e903", "d2e8e62c7b540d9f49f4d1c96a2fc5d6",

"529154a93960aff7432eb71d2618f1b4", "ce7603d2d7ae891f2592baa8e34f1333",

"164a3e93bc714dbd7722bdc02b96104f", "fc982bb07dc967a7f2ca29a1125f02d0",

"be4bed18af4852ae745c3dd6e1490243", "da29d0412b1022a733b587fe0eeee5c2",

"9142dff705398393fd53807d7a0c49d5", "84026f562a6e58484c541bf5dec66186",

"d407ce513d817ab0840bf2528758ee9b", "8e435185e4f65d0f342c8cee1d94a896"
    ];

    encrypted_values.iter()
        .filter_map(|encrypted|
            decrypt_hex(encrypted, key, iv).ok()
        )
        .collect()
}

fn check_pass(arr: &[u32], val: &[u32]) -> bool {
    if arr.len() != 28 {
        return false;
    }

    let constraints = vec![
        arr[0] == (((val[0] & val[1]) | val[2]) ^ val[3]),
        arr[9] == arr[8] && arr[8] == val[4],
        arr[2] == arr[14] && arr[14] == val[5],
        (arr[18] ^ val[6] ^ val[7] ^ val[8] ^ val[9]) == val[10],
        arr[24] == (((((arr[1].overflowing_sub(val[11])).0) & val[12]) | val[13]) ^ val[14]),
        arr[13] == arr[26] + val[15],
        arr[23] == (((((arr[0].overflowing_sub(val[16])).0) & val[17]) | val[18]) ^ val[19]),
        ((((arr[3] ^ val[20]) | val[21]) & val[22]) == arr[20]),
        arr[5] == (((arr[24] & val[23]) >> val[24]) ^ val[25]),
        arr[16] == val[26],
        arr[1] == ((((!arr[12]) & arr[6]) ^ val[27]) | val[28]),
        arr[27] == (((((arr[17] + arr[22]) & val[29]) ^ val[30]) | val[31])),
        arr[22] == arr[26] - val[32],
        arr[6] == (((arr[16] ^ arr[18]) & val[33]) ^ val[34]),
        arr[26] == (arr[17] | val[35]),
        arr[3] == ((((arr[20] & val[36]) >> val[37]) ^ val[38])) + val[39],
        (arr[19] ^ val[40] ^ val[41] ^ val[42] ^ val[43]) == val[44],
        arr[7] == ((((!arr[12]) & arr[6]) ^ val[45]) | val[46]),
        (arr[12] ^ val[47] ^ val[48] ^ val[49] ^ val[50]) == val[51],
        (arr[25] ^ val[52] + val[53]) == (arr[16] & val[54] ^ val[55]),
        arr[21] == (((((arr[12].overflowing_sub(val[56])).0) & val[57]) | val[58]) ^ val[59]),
        (arr[11] ^ val[60] ^ val[61] ^ val[62] ^ val[63]) == val[64],
        arr[17] == arr[26] && arr[26] == val[65],
        ((((arr[14] ^ arr[23]) & val[66]) ^ val[67]) == (arr[20] ^ val[68] - val[69])),
        arr[15] == val[70],
        arr[10] == ((((arr[15] + val[71]) | val[72]) & val[73]) ^ val[74]),
        arr[4] == val[75]
    ];

    constraints.iter().all(|&constraint| constraint)
}

fn main() {
    let decrypted_values = get_decrypted_values();

    let mut input = String::new();
    println!("\nCheck Flag: ");
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let input_trimmed = input.trim();
    if input_trimmed.len() != 28 {
        println!("\nInvalid input length!\n");
        return;
    }

    let flag: Vec<u32> = input_trimmed
        .chars()
        .map(|c| c as u32)
        .collect();

    if check_pass(&flag, &decrypted_values) {
        println!("\nCorrect flag!!!\n");
    } else {
        println!("\nNice Try Diddy\n");
    }
}
