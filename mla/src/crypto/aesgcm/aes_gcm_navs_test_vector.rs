//! AES-256-GCM tests, from "RustCrypto/AEADs/aes-gcm/tests/aes256gcm.rs"

use super::{AesGcm256, BLOCK_SIZE, Key, Nonce, TAG_LENGTH};

struct TestVector {
    key: &'static [u8],
    nonce: &'static [u8],
    plaintext: &'static [u8],
    aad: &'static [u8],
    ciphertext: &'static [u8],
    tag: &'static [u8],
}

/// NIST CAVS vectors
///
/// <https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES>
///
/// From: `gcmEncryptExtIV256.rsp`
const TEST_VECTORS: &[TestVector] = &[
    TestVector {
        key: &hex!("b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4"),
        nonce: &hex!("516c33929df5a3284ff463d7"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("bdc1ac884d332457a1d2664f168c76f0"),
    },
    TestVector {
        key: &hex!("5fe0861cdc2690ce69b3658c7f26f8458eec1c9243c5ba0845305d897e96ca0f"),
        nonce: &hex!("770ac1a5a3d476d5d96944a1"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("196d691e1047093ca4b3d2ef4baba216"),
    },
    TestVector {
        key: &hex!("7620b79b17b21b06d97019aa70e1ca105e1c03d2a0cf8b20b5a0ce5c3903e548"),
        nonce: &hex!("60f56eb7a4b38d4f03395511"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("f570c38202d94564bab39f75617bc87a"),
    },
    TestVector {
        key: &hex!("7e2db00321189476d144c5f27e787087302a48b5f7786cd91e93641628c2328b"),
        nonce: &hex!("ea9d525bf01de7b2234b606a"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("db9df5f14f6c9f2ae81fd421412ddbbb"),
    },
    TestVector {
        key: &hex!("a23dfb84b5976b46b1830d93bcf61941cae5e409e4f5551dc684bdcef9876480"),
        nonce: &hex!("5aa345908048de10a2bd3d32"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("f28217649230bd7a40a9a4ddabc67c43"),
    },
    TestVector {
        key: &hex!("dfe928f86430b78add7bb7696023e6153d76977e56103b180253490affb9431c"),
        nonce: &hex!("1dd0785af9f58979a10bd62d"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("a55eb09e9edef58d9f671d72207f8b3c"),
    },
    TestVector {
        key: &hex!("34048db81591ee68224956bd6989e1630fcf068d7ff726ae81e5b29f548cfcfb"),
        nonce: &hex!("1621d34cff2a5b250c7b76fc"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("4992ec3d57cccfa58fd8916c59b70b11"),
    },
    TestVector {
        key: &hex!("a1114f8749c72b8cef62e7503f1ad921d33eeede32b0b5b8e0d6807aa233d0ad"),
        nonce: &hex!("a190ed3ff2e238be56f90bd6"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("c8464d95d540fb191156fbbc1608842a"),
    },
    TestVector {
        key: &hex!("ddbb99dc3102d31102c0e14b238518605766c5b23d9bea52c7c5a771042c85a0"),
        nonce: &hex!("95d15ed75c6a109aac1b1d86"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("813d1da3775cacd78e96d86f036cff96"),
    },
    TestVector {
        key: &hex!("1faa506b8f13a2e6660af78d92915adf333658f748f4e48fa20135a29e9abe5f"),
        nonce: &hex!("e50f278d3662c99d750f60d3"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("aec7ece66b7344afd6f6cc7419cf6027"),
    },
    TestVector {
        key: &hex!("f30b5942faf57d4c13e7a82495aedf1b4e603539b2e1599317cc6e53225a2493"),
        nonce: &hex!("336c388e18e6abf92bb739a9"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("ddaf8ef4cb2f8a6d401f3be5ff0baf6a"),
    },
    TestVector {
        key: &hex!("daf4d9c12c5d29fc3fa936532c96196e56ae842e47063a4b29bfff2a35ed9280"),
        nonce: &hex!("5381f21197e093b96cdac4fa"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("7f1832c7f7cd7812a004b79c3d399473"),
    },
    TestVector {
        key: &hex!("6b524754149c81401d29a4b8a6f4a47833372806b2d4083ff17f2db3bfc17bca"),
        nonce: &hex!("ac7d3d618ab690555ec24408"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("db07a885e2bd39da74116d06c316a5c9"),
    },
    TestVector {
        key: &hex!("cff083303ff40a1f66c4aed1ac7f50628fe7e9311f5d037ebf49f4a4b9f0223f"),
        nonce: &hex!("45d46e1baadcfbc8f0e922ff"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("1687c6d459ea481bf88e4b2263227906"),
    },
    TestVector {
        key: &hex!("3954f60cddbb39d2d8b058adf545d5b82490c8ae9283afa5278689041d415a3a"),
        nonce: &hex!("8fb3d98ef24fba03746ac84f"),
        plaintext: b"",
        aad: b"",
        ciphertext: b"",
        tag: &hex!("7fb130855dfe7a373313361f33f55237"),
    },
    TestVector {
        key: &hex!("78dc4e0aaf52d935c3c01eea57428f00ca1fd475f5da86a49c8dd73d68c8e223"),
        nonce: &hex!("d79cf22d504cc793c3fb6c8a"),
        plaintext: b"",
        aad: &hex!("b96baa8c1c75a671bfb2d08d06be5f36"),
        ciphertext: b"",
        tag: &hex!("3e5d486aa2e30b22e040b85723a06e76"),
    },
    TestVector {
        key: &hex!("4457ff33683cca6ca493878bdc00373893a9763412eef8cddb54f91318e0da88"),
        nonce: &hex!("699d1f29d7b8c55300bb1fd2"),
        plaintext: b"",
        aad: &hex!("6749daeea367d0e9809e2dc2f309e6e3"),
        ciphertext: b"",
        tag: &hex!("d60c74d2517fde4a74e0cd4709ed43a9"),
    },
    TestVector {
        key: &hex!("4d01c96ef9d98d4fb4e9b61be5efa772c9788545b3eac39eb1cacb997a5f0792"),
        nonce: &hex!("32124a4d9e576aea2589f238"),
        plaintext: b"",
        aad: &hex!("d72bad0c38495eda50d55811945ee205"),
        ciphertext: b"",
        tag: &hex!("6d6397c9e2030f5b8053bfe510f3f2cf"),
    },
    TestVector {
        key: &hex!("8378193a4ce64180814bd60591d1054a04dbc4da02afde453799cd6888ee0c6c"),
        nonce: &hex!("bd8b4e352c7f69878a475435"),
        plaintext: b"",
        aad: &hex!("1c6b343c4d045cbba562bae3e5ff1b18"),
        ciphertext: b"",
        tag: &hex!("0833967a6a53ba24e75c0372a6a17bda"),
    },
    TestVector {
        key: &hex!("22fc82db5b606998ad45099b7978b5b4f9dd4ea6017e57370ac56141caaabd12"),
        nonce: &hex!("880d05c5ee599e5f151e302f"),
        plaintext: b"",
        aad: &hex!("3e3eb5747e390f7bc80e748233484ffc"),
        ciphertext: b"",
        tag: &hex!("2e122a478e64463286f8b489dcdd09c8"),
    },
    TestVector {
        key: &hex!("fc00960ddd698d35728c5ac607596b51b3f89741d14c25b8badac91976120d99"),
        nonce: &hex!("a424a32a237f0df530f05e30"),
        plaintext: b"",
        aad: &hex!("cfb7e05e3157f0c90549d5c786506311"),
        ciphertext: b"",
        tag: &hex!("dcdcb9e4004b852a0da12bdf255b4ddd"),
    },
    TestVector {
        key: &hex!("69749943092f5605bf971e185c191c618261b2c7cc1693cda1080ca2fd8d5111"),
        nonce: &hex!("bd0d62c02ee682069bd1e128"),
        plaintext: b"",
        aad: &hex!("6967dce878f03b643bf5cdba596a7af3"),
        ciphertext: b"",
        tag: &hex!("378f796ae543e1b29115cc18acd193f4"),
    },
    TestVector {
        key: &hex!("fc4875db84819834b1cb43828d2f0ae3473aa380111c2737e82a9ab11fea1f19"),
        nonce: &hex!("da6a684d3ff63a2d109decd6"),
        plaintext: b"",
        aad: &hex!("91b6fa2ab4de44282ffc86c8cde6e7f5"),
        ciphertext: b"",
        tag: &hex!("504e81d2e7877e4dad6f31cdeb07bdbd"),
    },
    TestVector {
        key: &hex!("9f9fe7d2a26dcf59d684f1c0945b5ffafe0a4746845ed317d35f3ed76c93044d"),
        nonce: &hex!("13b59971cd4dd36b19ac7104"),
        plaintext: b"",
        aad: &hex!("190a6934f45f89c90067c2f62e04c53b"),
        ciphertext: b"",
        tag: &hex!("4f636a294bfbf51fc0e131d694d5c222"),
    },
    TestVector {
        key: &hex!("ab9155d7d81ba6f33193695cf4566a9b6e97a3e409f57159ae6ca49655cca071"),
        nonce: &hex!("26a9f8d665d163ddb92d035d"),
        plaintext: b"",
        aad: &hex!("4a203ac26b951a1f673c6605653ec02d"),
        ciphertext: b"",
        tag: &hex!("437ea77a3879f010691e288d6269a996"),
    },
    TestVector {
        key: &hex!("0f1c62dd80b4a6d09ee9d787b1b04327aa361529ffa3407560414ac47b7ef7bc"),
        nonce: &hex!("c87613a3b70d2a048f32cb9a"),
        plaintext: b"",
        aad: &hex!("8f23d404be2d9e888d219f1b40aa29e8"),
        ciphertext: b"",
        tag: &hex!("36d8a309acbb8716c9c08c7f5de4911e"),
    },
    TestVector {
        key: &hex!("f3e954a38956df890255f01709e457b33f4bfe7ecb36d0ee50f2500471eebcde"),
        nonce: &hex!("9799abd3c52110c704b0f36a"),
        plaintext: b"",
        aad: &hex!("ddb70173f44157755b6c9b7058f40cb7"),
        ciphertext: b"",
        tag: &hex!("b323ae3abcb415c7f420876c980f4858"),
    },
    TestVector {
        key: &hex!("0625316534fbd82fe8fdea50fa573c462022c42f79e8b21360e5a6dce66dde28"),
        nonce: &hex!("da64a674907cd6cf248f5fbb"),
        plaintext: b"",
        aad: &hex!("f24d48e04f5a0d987ba7c745b73b0364"),
        ciphertext: b"",
        tag: &hex!("df360b810f27e794673a8bb2dc0d68b0"),
    },
    TestVector {
        key: &hex!("28f045ac7c4fe5d4b01a9dcd5f1ad3efff1c4f170fc8ab8758d97292868d5828"),
        nonce: &hex!("5d85de95b0bdc44514143919"),
        plaintext: b"",
        aad: &hex!("601d2158f17ab3c7b4dcb6950fbdcdde"),
        ciphertext: b"",
        tag: &hex!("42c3f527418cf2c3f5d5010ccba8f271"),
    },
    TestVector {
        key: &hex!("19310eed5f5f44eb47075c105eb31e36bbfd1310f741b9baa66a81138d357242"),
        nonce: &hex!("a1247120138fa4f0e96c992c"),
        plaintext: b"",
        aad: &hex!("29d746414333e0f72b4c3f44ec6bfe42"),
        ciphertext: b"",
        tag: &hex!("d5997e2f956df3fa2c2388e20f30c480"),
    },
    TestVector {
        key: &hex!("886cff5f3e6b8d0e1ad0a38fcdb26de97e8acbe79f6bed66959a598fa5047d65"),
        nonce: &hex!("3a8efa1cd74bbab5448f9945"),
        plaintext: b"",
        aad: &hex!("519fee519d25c7a304d6c6aa1897ee1eb8c59655"),
        ciphertext: b"",
        tag: &hex!("f6d47505ec96c98a42dc3ae719877b87"),
    },
    TestVector {
        key: &hex!("6937a57d35fe6dc3fc420b123bccdce874bd4c18f2e7c01ce2faf33d3944fd9d"),
        nonce: &hex!("a87247797b758467b96310f3"),
        plaintext: b"",
        aad: &hex!("ead961939a33dd578f8e93db8b28a1c85362905f"),
        ciphertext: b"",
        tag: &hex!("599de3ecf22cb867f03f7f6d9fd7428a"),
    },
    TestVector {
        key: &hex!("e65a331776c9dcdf5eba6c59e05ec079d97473bcdce84daf836be323456263a0"),
        nonce: &hex!("ca731f768da01d02eb8e727e"),
        plaintext: b"",
        aad: &hex!("d7274586517bf1d8da866f4a47ad0bcf2948a862"),
        ciphertext: b"",
        tag: &hex!("a8abe7a8085f25130a7206d37a8aaf6d"),
    },
    TestVector {
        key: &hex!("77bb1b6ef898683c981b2fc899319ffbb6000edca22566b634db3a3c804059e5"),
        nonce: &hex!("354a19283769b3b991b05a4c"),
        plaintext: b"",
        aad: &hex!("b5566251a8a8bec212dc08113229ff8590168800"),
        ciphertext: b"",
        tag: &hex!("e5c2dccf8fc7f296cac95d7071cb8d7d"),
    },
    TestVector {
        key: &hex!("2a43308d520a59ed51e47a3a915e1dbf20a91f0886506e481ad3de65d50975b4"),
        nonce: &hex!("bcbf99733d8ec90cb23e6ce6"),
        plaintext: b"",
        aad: &hex!("eb88288729289d26fe0e757a99ad8eec96106053"),
        ciphertext: b"",
        tag: &hex!("01b0196933aa49123eab4e1571250383"),
    },
    TestVector {
        key: &hex!("2379b35f85102db4e7aecc52b705bc695d4768d412e2d7bebe999236783972ff"),
        nonce: &hex!("918998c4801037b1cd102faa"),
        plaintext: b"",
        aad: &hex!("b3722309e0f066225e8d1659084ebb07a93b435d"),
        ciphertext: b"",
        tag: &hex!("dfb18aee99d1f67f5748d4b4843cb649"),
    },
    TestVector {
        key: &hex!("98b3cb7537167e6d14a2a8b2310fe94b715c729fdf85216568150b556d0797ba"),
        nonce: &hex!("bca5e2e5a6b30f18d263c6b2"),
        plaintext: b"",
        aad: &hex!("260d3d72db70d677a4e3e1f3e11431217a2e4713"),
        ciphertext: b"",
        tag: &hex!("d6b7560f8ac2f0a90bad42a6a07204bc"),
    },
    TestVector {
        key: &hex!("30341ae0f199b10a15175d00913d5029526ab7f761c0b936a7dd5f1b1583429d"),
        nonce: &hex!("dbe109a8ce5f7b241e99f7af"),
        plaintext: b"",
        aad: &hex!("fe4bdee5ca9c4806fa024715fbf66ab845285fa7"),
        ciphertext: b"",
        tag: &hex!("ae91daed658e26c0d126575147af9899"),
    },
    TestVector {
        key: &hex!("8232b6a1d2e367e9ce1ea8d42fcfc83a4bc8bdec465c6ba326e353ad9255f207"),
        nonce: &hex!("cd2fb5ff9cf0f39868ad8685"),
        plaintext: b"",
        aad: &hex!("02418b3dde54924a9628de06004c0882ae4ec3bb"),
        ciphertext: b"",
        tag: &hex!("d5308f63708675ced19b2710afd2db49"),
    },
    TestVector {
        key: &hex!("f9a132a50a508145ffd8294e68944ea436ce0f9a97e181f5e0d6c5d272311fc1"),
        nonce: &hex!("892991b54e94b9d57442ccaf"),
        plaintext: b"",
        aad: &hex!("4e0fbd3799da250fa27911b7e68d7623bfe60a53"),
        ciphertext: b"",
        tag: &hex!("89881d5f786e6d53e0d19c3b4e6887d8"),
    },
    TestVector {
        key: &hex!("0e3746e5064633ea9311b2b8427c536af92717de20eeb6260db1333c3d8a8114"),
        nonce: &hex!("f84c3a1c94533f7f25cec0ac"),
        plaintext: b"",
        aad: &hex!("8c0d41e6135338c8d3e63e2a5fa0a9667ec9a580"),
        ciphertext: b"",
        tag: &hex!("479ccfe9241de2c474f2edebbb385c09"),
    },
    TestVector {
        key: &hex!("b997e9b0746abaaed6e64b63bdf64882526ad92e24a2f5649df055c9ec0f1daa"),
        nonce: &hex!("f141d8d71b033755022f0a7d"),
        plaintext: b"",
        aad: &hex!("681d6583f527b1a92f66caae9b1d4d028e2e631e"),
        ciphertext: b"",
        tag: &hex!("b30442a6395ec13246c48b21ffc65509"),
    },
    TestVector {
        key: &hex!("87660ec1700d4e9f88a323a49f0b871e6aaf434a2d8448d04d4a22f6561028e0"),
        nonce: &hex!("2a07b42593cd24f0a6fe406c"),
        plaintext: b"",
        aad: &hex!("1dd239b57185b7e457ced73ebba043057f049edd"),
        ciphertext: b"",
        tag: &hex!("df7a501049b37a534098cb45cb9c21b7"),
    },
    TestVector {
        key: &hex!("ea4792e1f1717b77a00de4d109e627549b165c82af35f33ca7e1a6b8ed62f14f"),
        nonce: &hex!("7453cc8b46fe4b93bcc48381"),
        plaintext: b"",
        aad: &hex!("46d98970a636e7cd7b76fc362ae88298436f834f"),
        ciphertext: b"",
        tag: &hex!("518dbacd36be6fba5c12871678a55516"),
    },
    TestVector {
        key: &hex!("34892cdd1d48ca166f7ba73182cb97336c2c754ac160a3e37183d6fb5078cec3"),
        nonce: &hex!("ed3198c5861b78c71a6a4eec"),
        plaintext: b"",
        aad: &hex!("a6fa6d0dd1e0b95b4609951bbbe714de0ae0ccfa"),
        ciphertext: b"",
        tag: &hex!("c6387795096b348ecf1d1f6caaa3c813"),
    },
    TestVector {
        key: &hex!("f4069bb739d07d0cafdcbc609ca01597f985c43db63bbaaa0debbb04d384e49c"),
        nonce: &hex!("d25ff30fdc3d464fe173e805"),
        plaintext: b"",
        aad: &hex!(
            "3e1449c4837f0892f9d55127c75c4b25d69be334baf5f19394d2d8bb460cbf2120e14736d0f634aa792feca20e455f11"
        ),
        ciphertext: b"",
        tag: &hex!("805ec2931c2181e5bfb74fa0a975f0cf"),
    },
    TestVector {
        key: &hex!("62189dcc4beb97462d6c0927d8a270d39a1b07d72d0ad28840badd4f68cf9c8b"),
        nonce: &hex!("859fda5247c888823a4b8032"),
        plaintext: b"",
        aad: &hex!(
            "b28d1621ee110f4c9d709fad764bba2dd6d291bc003748faac6d901937120d41c1b7ce67633763e99e05c71363fceca8"
        ),
        ciphertext: b"",
        tag: &hex!("27330907d0002880bbb4c1a1d23c0be2"),
    },
    TestVector {
        key: &hex!("59012d85a1b90aeb0359e6384c9991e7be219319f5b891c92c384ade2f371816"),
        nonce: &hex!("3c9cde00c23912cff9689c7c"),
        plaintext: b"",
        aad: &hex!(
            "e5daf473a470860b55210a483c0d1a978d8add843c2c097f73a3cda49ac4a614c8e887d94e6692309d2ed97ebe1eaf5d"
        ),
        ciphertext: b"",
        tag: &hex!("048239e4e5c2c8b33890a7c950cda852"),
    },
    TestVector {
        key: &hex!("4be09b408ad68b890f94be5efa7fe9c917362712a3480c57cd3844935f35acb7"),
        nonce: &hex!("8f350bd3b8eea173fc7370bc"),
        plaintext: b"",
        aad: &hex!(
            "2819d65aec942198ca97d4435efd9dd4d4393b96cf5ba44f09bce4ba135fc8636e8275dcb515414b8befd32f91fc4822"
        ),
        ciphertext: b"",
        tag: &hex!("a133cb7a7d0471dbac61fb41589a2efe"),
    },
    TestVector {
        key: &hex!("13cb965a4d9d1a36efad9f6ca1ba76386a5bb160d80b0917277102357ac7afc8"),
        nonce: &hex!("f313adec42a66d13c3958180"),
        plaintext: b"",
        aad: &hex!(
            "717b48358898e5ccfea4289049adcc1bb0db3b3ebd1767ac24fb2b7d37dc80ea2316c17f14fb51b5e18cd5bb09afe414"
        ),
        ciphertext: b"",
        tag: &hex!("81b4ef7a84dc4a0b1fddbefe37f53852"),
    },
    TestVector {
        key: &hex!("d27f1bebbbdef0edca393a6261b0338abbc491262eab0737f55246458f6668cc"),
        nonce: &hex!("fc062f857886e278f3a567d2"),
        plaintext: b"",
        aad: &hex!(
            "2bae92dea64aa99189de8ea4c046745306002e02cfb46a41444ce8bfcc329bd4205963d9ab5357b026a4a34b1a861771"
        ),
        ciphertext: b"",
        tag: &hex!("5c5a6c4613f1e522596330d45f243fdd"),
    },
    TestVector {
        key: &hex!("7b4d19cd3569f74c7b5df61ab78379ee6bfa15105d21b10bf6096699539006d0"),
        nonce: &hex!("fbed5695c4a739eded97b1e3"),
        plaintext: b"",
        aad: &hex!(
            "c6f2e5d663bfaf668d014550ef2e66bf89978799a785f1f2c79a2cb3eb3f2fd4076207d5f7e1c284b4af5cffc4e46198"
        ),
        ciphertext: b"",
        tag: &hex!("7101b434fb90c7f95b9b7a0deeeb5c81"),
    },
    TestVector {
        key: &hex!("d3431488d8f048590bd76ec66e71421ef09f655d7cf8043bf32f75b4b2e7efcc"),
        nonce: &hex!("cc766e98b40a81519fa46392"),
        plaintext: b"",
        aad: &hex!(
            "93320179fdb40cbc1ccf00b872a3b4a5f6c70b56e43a84fcac5eb454a0a19a747d452042611bf3bbaafd925e806ffe8e"
        ),
        ciphertext: b"",
        tag: &hex!("3afcc336ce8b7191eab04ad679163c2a"),
    },
    TestVector {
        key: &hex!("a440948c0378561c3956813c031f81573208c7ffa815114ef2eee1eb642e74c6"),
        nonce: &hex!("c1f4ffe54b8680832eed8819"),
        plaintext: b"",
        aad: &hex!(
            "253438f132b18e8483074561898c5652b43a82cc941e8b4ae37e792a8ed6ec5ce2bcec9f1ffcf4216e46696307bb774a"
        ),
        ciphertext: b"",
        tag: &hex!("129445f0a3c979a112a3afb10a24e245"),
    },
    TestVector {
        key: &hex!("798706b651033d9e9bf2ce064fb12be7df7308cf45df44776588cd391c49ff85"),
        nonce: &hex!("5a43368a39e7ffb775edfaf4"),
        plaintext: b"",
        aad: &hex!(
            "926b74fe6381ebd35757e42e8e557601f2287bfc133a13fd86d61c01aa84f39713bf99a8dc07b812f0274c9d3280a138"
        ),
        ciphertext: b"",
        tag: &hex!("89fe481a3d95c03a0a9d4ee3e3f0ed4a"),
    },
    TestVector {
        key: &hex!("c3aa2a39a9fef4a466618d1288bb62f8da7b1cb760ccc8f1be3e99e076f08eff"),
        nonce: &hex!("9965ba5e23d9453d7267ca5b"),
        plaintext: b"",
        aad: &hex!(
            "93efb6a2affc304cb25dfd49aa3e3ccdb25ceac3d3cea90dd99e38976978217ad5f2b990d10b91725c7fd2035ecc6a30"
        ),
        ciphertext: b"",
        tag: &hex!("00a94c18a4572dcf4f9e2226a03d4c07"),
    },
    TestVector {
        key: &hex!("14e06858008f7e77186a2b3a7928a0c7fcee22136bc36f53553f20fa5c37edcd"),
        nonce: &hex!("32ebe0dc9ada849b5eda7b48"),
        plaintext: b"",
        aad: &hex!(
            "6c0152abfa485b8cd67c154a5f0411f22121379774d745f40ee577b028fd0e188297581561ae972223d75a24b488aed7"
        ),
        ciphertext: b"",
        tag: &hex!("2625b0ba6ee02b58bc529e43e2eb471b"),
    },
    TestVector {
        key: &hex!("fbb56b11c51a093ce169a6990399c4d741f62b3cc61f9e8a609a1b6ae8e7e965"),
        nonce: &hex!("9c5a953247e91aceceb9defb"),
        plaintext: b"",
        aad: &hex!(
            "46cb5c4f617916a9b1b2e03272cb0590ce716498533047d73c81e4cbe9278a3686116f5632753ea2df52efb3551aea2d"
        ),
        ciphertext: b"",
        tag: &hex!("4f3b82e6be4f08756071f2c46c31fedf"),
    },
    TestVector {
        key: &hex!("b303bf02f6a8dbb5bc4baccab0800db5ee06de648e2fae299b95f135c9b107cc"),
        nonce: &hex!("906495b67ef4ce00b44422fa"),
        plaintext: b"",
        aad: &hex!(
            "872c6c370926535c3fa1baec031e31e7c6c82808c8a060742dbef114961c314f1986b2131a9d91f30f53067ec012c6b7"
        ),
        ciphertext: b"",
        tag: &hex!("64dde37169082d181a69107f60c5c6bb"),
    },
    TestVector {
        key: &hex!("29f5f8075903063cb6d7050669b1f74e08a3f79ef566292dfdef1c06a408e1ab"),
        nonce: &hex!("35f25c48b4b5355e78b9fb3a"),
        plaintext: b"",
        aad: &hex!(
            "107e2e23159fc5c0748ca7a077e5cc053fa5c682ff5269d350ee817f8b5de4d3972041d107b1e2f2e54ca93b72cd0408"
        ),
        ciphertext: b"",
        tag: &hex!("fee5a9baebb5be0165deaa867e967a9e"),
    },
    TestVector {
        key: &hex!("03ccb7dbc7b8425465c2c3fc39ed0593929ffd02a45ff583bd89b79c6f646fe9"),
        nonce: &hex!("fd119985533bd5520b301d12"),
        plaintext: b"",
        aad: &hex!(
            "98e68c10bf4b5ae62d434928fc6405147c6301417303ef3a703dcfd2c0c339a4d0a89bd29fe61fecf1066ab06d7a5c31a48ffbfed22f749b17e9bd0dc1c6f8fbd6fd4587184db964d5456132106d782338c3f117ec05229b0899"
        ),
        ciphertext: b"",
        tag: &hex!("cf54e7141349b66f248154427810c87a"),
    },
    TestVector {
        key: &hex!("57e112cd45f2c57ddb819ea651c206763163ef016ceead5c4eae40f2bbe0e4b4"),
        nonce: &hex!("188022c2125d2b1fcf9e4769"),
        plaintext: b"",
        aad: &hex!(
            "09c8f445ce5b71465695f838c4bb2b00624a1c9185a3d552546d9d2ee4870007aaf3007008f8ae9affb7588b88d09a90e58b457f88f1e3752e3fb949ce378670b67a95f8cf7f5c7ceb650efd735dbc652cae06e546a5dbd861bd"
        ),
        ciphertext: b"",
        tag: &hex!("9efcddfa0be21582a05749f4050d29fe"),
    },
    TestVector {
        key: &hex!("a4ddf3cab7453aaefad616fd65d63d13005e9459c17d3173cd6ed7f2a86c921f"),
        nonce: &hex!("06177b24c58f3be4f3dd4920"),
        plaintext: b"",
        aad: &hex!(
            "f95b046d80485e411c56b834209d3abd5a8a9ddf72b1b916679adfdde893044315a5f4967fd0405ec297aa332f676ff0fa5bd795eb609b2e4f088db1cdf37ccff0735a5e53c4c12173a0026aea42388a7d7153a8830b8a901cf9"
        ),
        ciphertext: b"",
        tag: &hex!("9d1bd8ecb3276906138d0b03fcb8c1bb"),
    },
    TestVector {
        key: &hex!("24a92b24e85903cd4aaabfe07c310df5a4f8f459e03a63cbd1b47855b09c0be8"),
        nonce: &hex!("22e756dc898d4cf122080612"),
        plaintext: b"",
        aad: &hex!(
            "2e01b2536dbe376be144296f5c38fb099e008f962b9f0e896334b6408393bff1020a0e442477abfdb1727213b6ccc577f5e16cb057c8945a07e307264b65979aed96b5995f40250ffbaaa1a1f0eccf394015f6290f5e64dfe5ca"
        ),
        ciphertext: b"",
        tag: &hex!("0d7f1aed4708a03b0c80b2a18785c96d"),
    },
    TestVector {
        key: &hex!("15276fc64438578e0ec53366b90a0e23d93910fec10dc3003d9b3f3fa72db702"),
        nonce: &hex!("c5e931946d5caebc227656d2"),
        plaintext: b"",
        aad: &hex!(
            "3f967c83ba02e77c14e9d41185eb87f172250e93edb0f82b6742c124298ab69418358eddefa39fedc3cade9d80f036d864a59ead37c87727c56c701a8cd9634469ff31c704f5ee39354157e6558467b92824da36b1c071bedfe9"
        ),
        ciphertext: b"",
        tag: &hex!("a0ffa19adcf31d061cd0dd46d24015ef"),
    },
    TestVector {
        key: &hex!("ec09804a048bb854c71618b5a3a1c590910fc8a68455139b719486d2280ea59a"),
        nonce: &hex!("d0b1247e7121a9276ac18ca3"),
        plaintext: b"",
        aad: &hex!(
            "66b1d39d414596308e866b04476e053b71acd1cd07ce80939577ebbeace0430f7e4c0c185fe1d97ac7569950c83db40bbed0f1d173e1aa0dc28b4773705032d97551f7fcef7f55e4b69f88df650032dfc5232c156641104b5397"
        ),
        ciphertext: b"",
        tag: &hex!("8440e6d864ab778f9be478f203162d86"),
    },
    TestVector {
        key: &hex!("4adf86bfa547725e4b80365a5a327c107040facfff007dc35102066bd6a995c4"),
        nonce: &hex!("b1018cc331911255a55a0795"),
        plaintext: b"",
        aad: &hex!(
            "053ca4428c990b4456d3c1895d5d52deff675896de9faa53d8cf241255f4a31dc3399f15d83be380256616e5af043abfb37552655adf4f2e68dda24bc3736951134f359d9c0e288bb798b6c3ea46239231a3cb280066db9862e7"
        ),
        ciphertext: b"",
        tag: &hex!("c7424f38084930bfc5edc1fcf1e7608d"),
    },
    TestVector {
        key: &hex!("3c92e0d1e39a3c766573c4646c768c402ccff48a56682a93433512abf0456e00"),
        nonce: &hex!("d57f319e590191841d2b98bd"),
        plaintext: b"",
        aad: &hex!(
            "840d9394aa240e52ba152151c12acd1cd44881e8549dc832b71a45da7efcc74fb7e844d9fec25e5d497b8fb8f47f328c8d99045a19e366e6ce5e19dc26f67a81a94fa6c97c314d886e7b56eff144c09f6fa519db6308bc73422e"
        ),
        ciphertext: b"",
        tag: &hex!("cb4ef72dbda4914d7434f9686f823e2f"),
    },
    TestVector {
        key: &hex!("b66ba39733888a9e0a2e30452844161dc33cb383c02ce16c4efad5452509b5b5"),
        nonce: &hex!("937cb665e37059b2e40359f2"),
        plaintext: b"",
        aad: &hex!(
            "dbcd9694a8834860034e8ede3a5bd419fcf91c005ad99f488aa623f581622093f9d41e6a68e20fd202f302bcfc4417ca89090bfcd4d5224e8ff4eb5bbae4ecb27baa239f59c2f99cd47c0a269c497906b41a8f320a3dd2dc2de2"
        ),
        ciphertext: b"",
        tag: &hex!("bdc8249302d9d666cf7168317c118743"),
    },
    TestVector {
        key: &hex!("2f9fcd1043455695638c991a1b1d35ad57c18ef0727322747b7991abc3d787f3"),
        nonce: &hex!("d06cf548f62869f4bed7a318"),
        plaintext: b"",
        aad: &hex!(
            "432023c12cf1f614e1005112a17dbe6c5d54022a95cf6335a5bc55004c75f09a5699739ecf928e1c78d03dad5096a17a084afe1cc22041bbdfb5985bd08b0dcc59d2b08cd86b7aad597c4cd7b4ba6d6a7370b83995a6511a1f9e"
        ),
        ciphertext: b"",
        tag: &hex!("322eb84fb6884f10cfb766c2e3ec779e"),
    },
    TestVector {
        key: &hex!("21c5839a63e1230c06b086341c96ab74585e69bced94332caeb1fa77d510c24f"),
        nonce: &hex!("5ab6e5ed6ee733be7250858c"),
        plaintext: b"",
        aad: &hex!(
            "c92f08e30f67d42516133c48e97b65cc9e124365e110aba5e7b2cbe83debcc99edf4eb0007af052bda22d85900271b1897af4fd9ace6a2d09d984ac3de79d05de0b105a81b12542b2c48e27d409fd6992dd062d6055d6fc66842"
        ),
        ciphertext: b"",
        tag: &hex!("53b0e450309d146459f2a1e46c9d9e23"),
    },
    TestVector {
        key: &hex!("25a144f0fdba184125d81a87e7ed82fad33c701a094a67a81fe4692dc69afa31"),
        nonce: &hex!("8bf575c5c2b45b4efc6746e4"),
        plaintext: b"",
        aad: &hex!(
            "2a367cb0d3b7c5b8320b3cf95e82b6ba0bba1d09a2055885dedd9ef5641623682212103238b8f775cce42ddfd4f66382f2c3a5e8d6dff9163ced83580a75705574026b55db90f75f8abb3014c9a707021dedc075da38bebbf0a0"
        ),
        ciphertext: b"",
        tag: &hex!("0e2ce9cac8dfcedb0572ec6cab621efd"),
    },
    TestVector {
        key: &hex!("42bc841b3b03a807cd366a35ecec8a6aebef7c4cba0ec8cb8da0da41df8ccef1"),
        nonce: &hex!("1bd46f85df5f4b3a126ee315"),
        plaintext: b"",
        aad: &hex!(
            "ede3dcddbdc7d8e5d034c01661332ec349cb4e7a9fbaaf7abe2c647587db86cd427ce66908e070bc49ef838747e06b45ac486dfbea6f8698b4625e21e69db8327ec05cfd74accbe67ab644948cdb554af179a1e264e08fe16641"
        ),
        ciphertext: b"",
        tag: &hex!("633ab6aaf5b32b53a794f6be6262fc5f"),
    },
    TestVector {
        key: &hex!("c25b8500be73210596fc4a9fb4d84d1a3379a91e3f0a6cc4177d996046627679"),
        nonce: &hex!("b56c48c0c4cd318b20437002"),
        plaintext: b"",
        aad: &hex!(
            "bcd14dd043fdc8c327957e1c1428698543ec8602521a7c74788d296d37d4828f10f90656883d2531c702ebda2dc0a68dab00154577454455fad986ff8e0973098dbf370ff703ed98222b945726ed9be7909210ddbc672e99fdd9"
        ),
        ciphertext: b"",
        tag: &hex!("8171d4ff60fe7ef6de0288326aa73223"),
    },
    TestVector {
        key: &hex!("dd95259bc8eefa3e493cb1a6ba1d8ee2b341d5230d50363094a2cc3433b3d9b9"),
        nonce: &hex!("a1a6ced084f4f13990750a9e"),
        plaintext: b"",
        aad: &hex!(
            "d46db90e13684b26149cb3b7f776e228a0538fa1892c418aaad07aa08d3076f4a52bee8f130ff560db2b8d1009e9260fa6233fc22733e050c9e4f7cc699062765e261dffff1159e9060b26c8065dfab04055b58c82c340d987c9"
        ),
        ciphertext: b"",
        tag: &hex!("9e120b01899fe2cb3e3a0b0c05045940"),
    },
    TestVector {
        key: &hex!("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22"),
        nonce: &hex!("0d18e06c7c725ac9e362e1ce"),
        plaintext: &hex!("2db5168e932556f8089a0622981d017d"),
        aad: b"",
        ciphertext: &hex!("fa4362189661d163fcd6a56d8bf0405a"),
        tag: &hex!("d636ac1bbedd5cc3ee727dc2ab4a9489"),
    },
    TestVector {
        key: &hex!("460fc864972261c2560e1eb88761ff1c992b982497bd2ac36c04071cbb8e5d99"),
        nonce: &hex!("8a4a16b9e210eb68bcb6f58d"),
        plaintext: &hex!("99e4e926ffe927f691893fb79a96b067"),
        aad: b"",
        ciphertext: &hex!("133fc15751621b5f325c7ff71ce08324"),
        tag: &hex!("ec4e87e0cf74a13618d0b68636ba9fa7"),
    },
    TestVector {
        key: &hex!("f78a2ba3c5bd164de134a030ca09e99463ea7e967b92c4b0a0870796480297e5"),
        nonce: &hex!("2bb92fcb726c278a2fa35a88"),
        plaintext: &hex!("f562509ed139a6bbe7ab545ac616250c"),
        aad: b"",
        ciphertext: &hex!("e2f787996e37d3b47294bf7ebba5ee25"),
        tag: &hex!("00f613eee9bdad6c9ee7765db1cb45c0"),
    },
    TestVector {
        key: &hex!("48e6af212da1386500454c94a201640c2151b28079240e40d72d2a5fd7d54234"),
        nonce: &hex!("ef0ff062220eb817dc2ece94"),
        plaintext: &hex!("c7afeecec1408ad155b177c2dc7138b0"),
        aad: b"",
        ciphertext: &hex!("9432a620e6a22307e06a321d66846fd4"),
        tag: &hex!("e3ea499192f2cd8d3ab3edfc55897415"),
    },
    TestVector {
        key: &hex!("79cd8d750fc8ea62a2714edcd9b32867c7c4da906c56e23a644552f5b812e75a"),
        nonce: &hex!("9bbfdb81015d2b57dead2de5"),
        plaintext: &hex!("f980ad8c55ebd31ee6f98f44e92bff55"),
        aad: b"",
        ciphertext: &hex!("41a34d1e759c859e91b8cf5d3ded1970"),
        tag: &hex!("68cd98406d5b322571e750c30aa49834"),
    },
    TestVector {
        key: &hex!("130ae450c18efb851057aaa79575a0a090194be8b2c95469a0e8e380a8f48f42"),
        nonce: &hex!("b269115396f81b39e0c38f47"),
        plaintext: &hex!("036cf36280dee8355c82abc4c1fdb778"),
        aad: b"",
        ciphertext: &hex!("09f7568fd8181652e556f0dda5a49ed5"),
        tag: &hex!("d10b61947cae275b7034f5259ba6fc28"),
    },
    TestVector {
        key: &hex!("9c7121289aefc67090cabed53ad11658be72a5372761b9d735e81d2bfc0e3267"),
        nonce: &hex!("ade1702d2051b8dd203b5419"),
        plaintext: &hex!("b95bcaa2b31403d76859a4c301c50b56"),
        aad: b"",
        ciphertext: &hex!("628285e6489090dde1b9a60674785003"),
        tag: &hex!("9f516af3f3b93d610edbc5ba6e2d115f"),
    },
    TestVector {
        key: &hex!("0400b42897011fc20fd2280a52ef905d6ebf1b055b48c97067bd786d678ec4ea"),
        nonce: &hex!("0abfb0a41496b453358409d9"),
        plaintext: &hex!("20c8230191e35f4e9b269d59cf5521f6"),
        aad: b"",
        ciphertext: &hex!("dd8c38087daffbbb3ebb57ebf5ee5f78"),
        tag: &hex!("bfb07aa5049ee350ec6fb1397f37087b"),
    },
    TestVector {
        key: &hex!("56690798978c154ff250ba78e463765f2f0ce69709a4551bd8cb3addeda087b6"),
        nonce: &hex!("cf37c286c18ad4ea3d0ba6a0"),
        plaintext: &hex!("2d328124a8d58d56d0775eed93de1a88"),
        aad: b"",
        ciphertext: &hex!("3b0a0267f6ecde3a78b30903ebd4ca6e"),
        tag: &hex!("1fd2006409fc636379f3d4067eca0988"),
    },
    TestVector {
        key: &hex!("8a02a33bdf87e7845d7a8ae3c8727e704f4fd08c1f2083282d8cb3a5d3cedee9"),
        nonce: &hex!("599f5896851c968ed808323b"),
        plaintext: &hex!("4ade8b32d56723fb8f65ce40825e27c9"),
        aad: b"",
        ciphertext: &hex!("cb9133796b9075657840421a46022b63"),
        tag: &hex!("a79e453c6fad8a5a4c2a8e87821c7f88"),
    },
    TestVector {
        key: &hex!("23aaa78a5915b14f00cf285f38ee275a2db97cb4ab14d1aac8b9a73ff1e66467"),
        nonce: &hex!("4a675ec9be1aab9632dd9f59"),
        plaintext: &hex!("56659c06a00a2e8ed1ac60572eee3ef7"),
        aad: b"",
        ciphertext: &hex!("e6c01723bfbfa398d9c9aac8c683bb12"),
        tag: &hex!("4a2f78a9975d4a1b5f503a4a2cb71553"),
    },
    TestVector {
        key: &hex!("fe647f72e95c469027f4d7778429a2e8e90d090268d4fa7df44f65c0af84190a"),
        nonce: &hex!("4f40ae2a83a9b480e4686c90"),
        plaintext: &hex!("31fd6cce3f0d2b0d18e0af01c4b5609e"),
        aad: b"",
        ciphertext: &hex!("54c769fd542f0d3022f1335a7c410b61"),
        tag: &hex!("106cb7cbcd967da6cad646039c753474"),
    },
    TestVector {
        key: &hex!("fce205515f0551b1797128a2132d8e002ea5ab1beb99c5e7e8329398cf478e10"),
        nonce: &hex!("20209a0d4a3b9bfddeef39a0"),
        plaintext: &hex!("7d663e31a2f6ffef17e536684dae2e87"),
        aad: b"",
        ciphertext: &hex!("6529712030fb659dc11ab719f6a4c402"),
        tag: &hex!("58699464d062aba505508c576c4e07dd"),
    },
    TestVector {
        key: &hex!("cd33003ff18f6f3369dd9a35381261ba660ce0a769864475152e677066540337"),
        nonce: &hex!("20bffe9064ce76d275204138"),
        plaintext: &hex!("acaf53d4dd2fe12cd44450b0d9adcc92"),
        aad: b"",
        ciphertext: &hex!("a669fda0444b180165f90815dc992b33"),
        tag: &hex!("6e31f5a56c4790cedcc2368c51d0639b"),
    },
    TestVector {
        key: &hex!("381873b5f9579d8241f0c61f0d9e327bb9f678691714aaa48ea7d92678d43fe7"),
        nonce: &hex!("3fc8bec23603158e012d65e5"),
        plaintext: &hex!("7b622e9b408fe91f6fa800ecef838d36"),
        aad: b"",
        ciphertext: &hex!("8ca4de5b4e2ab22431a009f3ddd01bae"),
        tag: &hex!("b3a7f80e3edf322622731550164cd747"),
    },
    TestVector {
        key: &hex!("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b"),
        nonce: &hex!("ac93a1a6145299bde902f21a"),
        plaintext: &hex!("2d71bcfa914e4ac045b2aa60955fad24"),
        aad: &hex!("1e0889016f67601c8ebea4943bc23ad6"),
        ciphertext: &hex!("8995ae2e6df3dbf96fac7b7137bae67f"),
        tag: &hex!("eca5aa77d51d4a0a14d9c51e1da474ab"),
    },
    TestVector {
        key: &hex!("7da3bccaffb3464178ca7c722379836db50ce0bfb47640b9572163865332e486"),
        nonce: &hex!("c04fd2e701c3dc62b68738b3"),
        plaintext: &hex!("fd671cab1ee21f0df6bb610bf94f0e69"),
        aad: &hex!("fec0311013202e4ffdc4204926ae0ddf"),
        ciphertext: &hex!("6be61b17b7f7d494a7cdf270562f37ba"),
        tag: &hex!("5e702a38323fe1160b780d17adad3e96"),
    },
    TestVector {
        key: &hex!("a359b9584beec189527f8842dda6b6d4c6a5db2f889635715fa3bcd7967c0a71"),
        nonce: &hex!("8616c4cde11b34a944caba32"),
        plaintext: &hex!("33a46b7539d64c6e1bdb91ba221e3007"),
        aad: &hex!("e1796fca20cb3d3ab0ade69b2a18891e"),
        ciphertext: &hex!("b0d316e95f3f3390ba10d0274965c62b"),
        tag: &hex!("aeaedcf8a012cc32ef25a62790e9334c"),
    },
    TestVector {
        key: &hex!("8c83238e7b3b58278200b54940d779d0a0750673aab0bf2f5808dd15dc1a8c49"),
        nonce: &hex!("70f8f4ebe408f61a35077956"),
        plaintext: &hex!("6e57f8572dd5b2247410f0d4c7424186"),
        aad: &hex!("e1cbf83924f1b8d1014b97db56c25a15"),
        ciphertext: &hex!("4a11acb9611251df01f79f16f8201ffb"),
        tag: &hex!("9732be4ad0569586753d90fabb06f62c"),
    },
    TestVector {
        key: &hex!("fe21919bb320af8744c9e862b5b7cf8b81ad3ad1fb0e7d7d710a688d3eed154b"),
        nonce: &hex!("38bc3917aa1925f40850c082"),
        plaintext: &hex!("aea53b1ea79a71c3a4b83c92a0c979f1"),
        aad: &hex!("f24102fa7e6b819bb3ff47f90844db9c"),
        ciphertext: &hex!("2fb8b697bf8f7a2eea25fe702a3ae0a9"),
        tag: &hex!("5be77e827737ad7c4f79e0e343fe010d"),
    },
    TestVector {
        key: &hex!("499e8a3f39ac4abc62dd4e1a6133042e74785972b6b501bfaffefc8bb29fd312"),
        nonce: &hex!("5c728dbbef9dcc0ff483e891"),
        plaintext: &hex!("b44014c7fc6b3f15d126a881fbe2bd2b"),
        aad: &hex!("82300dab592f840ae991efa3623a6203"),
        ciphertext: &hex!("578fe5e1aef7619f392c027c838a239e"),
        tag: &hex!("49fdc724f05eb56ea9e3fd14b61ad567"),
    },
    TestVector {
        key: &hex!("2775d3e7a8fc665bb9a59edc22eb136add194824ed8f2adb449177404c739716"),
        nonce: &hex!("73f16c054e166696df679a2e"),
        plaintext: &hex!("c9f3bce40310b6c0a3fd62742e4f3617"),
        aad: &hex!("23199a1c9b7244913952ca4f7e7444f4"),
        ciphertext: &hex!("72c85c10756266d00a9a4340b2cb3137"),
        tag: &hex!("5881e4565b42394e62d5daf0d1ebc593"),
    },
    TestVector {
        key: &hex!("425a341c67e6d873870f54e2cc5a2984c734e81729c0dbaaeee050309f1ce674"),
        nonce: &hex!("0c09b7b4e9e097317b791433"),
        plaintext: &hex!("76dda644b3faca509b37def0319f30cc"),
        aad: &hex!("4300a721547846761e4bf8df2b6ec1d6"),
        ciphertext: &hex!("1dd80daa0fc9e47e43897c64a6663f5e"),
        tag: &hex!("5d69b34d8c3b12f783faaea7e93685db"),
    },
    TestVector {
        key: &hex!("dd5c48988a6e9f9f60be801ba5c090f224a1b53d6601ec5858eab7b7784a8d5e"),
        nonce: &hex!("43562d48cd4110a66d9ca64e"),
        plaintext: &hex!("2cda2761fd0be2b03f9714fce8d0e303"),
        aad: &hex!("55e568309fc6cb0fb0e0e7d2511d4116"),
        ciphertext: &hex!("f2cfb6f5446e7aa172adfcd66b92a98d"),
        tag: &hex!("e099c64d2966e780ce7d2eaae97f47d8"),
    },
    TestVector {
        key: &hex!("2bdad9c3e5de6e4e101b7f16e727c690db95eacf4b0ccbdec7aab6fb9fc80486"),
        nonce: &hex!("a5cf3967d244074d2153c576"),
        plaintext: &hex!("84c867ec36cc6fe3487f5192fdfd390b"),
        aad: &hex!("6bdae72b5ed0e4d1f10064ebd02cf85c"),
        ciphertext: &hex!("53c8fa437c1b5fa91abbd6508b3878ce"),
        tag: &hex!("7859593d127324be8b9cf1d43ead4d82"),
    },
    TestVector {
        key: &hex!("01e92afdb5d956be12d38b09252966c5728d26f3c72e54bb62bbc55ae590e716"),
        nonce: &hex!("886e55364eeb90e87ac79bbe"),
        plaintext: &hex!("6c6570385f3d6d937e54a3a2e95bc9eb"),
        aad: &hex!("c76aabb7f44b942a81feb50249d2131a"),
        ciphertext: &hex!("423b749a507f437b431114962180d352"),
        tag: &hex!("54d859320a49281368297da7d4e37326"),
    },
    TestVector {
        key: &hex!("46921319217598cb64256fe49abca1f18a9d1dbca360f8630afb5c6137cb42b5"),
        nonce: &hex!("290827cf981415760ec3b37a"),
        plaintext: &hex!("480d32b191c2e201aed03680f93ea2da"),
        aad: &hex!("535ee80b12f581baaf8027e6e3900e31"),
        ciphertext: &hex!("89ace4f73583fb1ac260dea99b54055e"),
        tag: &hex!("7b8b8358363c175a66e6fb48d1bc2222"),
    },
    TestVector {
        key: &hex!("e18cd9b01b59bc0de1502efb74c3642997fe7dfb8d80c8a73caffe7726807d33"),
        nonce: &hex!("bd087b384c40841b3839ba02"),
        plaintext: &hex!("62f7f3a12b8c5f6747fcfe192d850b19"),
        aad: &hex!("fe69f837961b1d83f27fbf68e6791a1c"),
        ciphertext: &hex!("bacfccf6397424e96caf761e71dd3e3a"),
        tag: &hex!("9c9a5b65420f83e766c7c051680e8e58"),
    },
    TestVector {
        key: &hex!("68ee463b3153d9a042e5e3685def6f90f7659a203441de337fb94831cbeae9b2"),
        nonce: &hex!("9c4a9254c485236cf838de7e"),
        plaintext: &hex!("73731054514f3fb0102c7a1df809f212"),
        aad: &hex!("d55820e7acbb27d23c7df32938cf7d42"),
        ciphertext: &hex!("13b7823cac37f40eb811e3c966d16a67"),
        tag: &hex!("76288c33a66ff6451e2cec6c4ba4935e"),
    },
    TestVector {
        key: &hex!("64bd594daf279e3172f9aa713b35b7fce8f43083792bc7d1f10919131f400a7b"),
        nonce: &hex!("339a2c40e9d9507c34228649"),
        plaintext: &hex!("2b794cb4c98450463a3e225ab33f3f30"),
        aad: &hex!("2b9544807b362ebfd88146e2b02c9270"),
        ciphertext: &hex!("434d703b8d1069ad8036288b7c2d1ae6"),
        tag: &hex!("7d31e397c0c943cbb16cfb9539a6a17d"),
    },
    TestVector {
        key: &hex!("83688deb4af8007f9b713b47cfa6c73e35ea7a3aa4ecdb414dded03bf7a0fd3a"),
        nonce: &hex!("0b459724904e010a46901cf3"),
        plaintext: &hex!("33d893a2114ce06fc15d55e454cf90c3"),
        aad: &hex!("794a14ccd178c8ebfd1379dc704c5e208f9d8424"),
        ciphertext: &hex!("cc66bee423e3fcd4c0865715e9586696"),
        tag: &hex!("0fb291bd3dba94a1dfd8b286cfb97ac5"),
    },
    TestVector {
        key: &hex!("013f549af9ecc2ee0259d5fc2311059cb6f10f6cd6ced3b543babe7438a88251"),
        nonce: &hex!("e45e759a3bfe4b652dc66d5b"),
        plaintext: &hex!("79490d4d233ba594ece1142e310a9857"),
        aad: &hex!("b5fe530a5bafce7ae79b3c15471fa68334ab378e"),
        ciphertext: &hex!("619443034e4437b893a45a4c89fad851"),
        tag: &hex!("6da8a991b690ff6a442087a356f8e9e3"),
    },
    TestVector {
        key: &hex!("4b2815c531d2fceab303ec8bca739a97abca9373b7d415ad9d6c6fa9782518cc"),
        nonce: &hex!("47d647a72b3b5fe19f5d80f7"),
        plaintext: &hex!("d3f6a645779e07517bd0688872e0a49b"),
        aad: &hex!("20fd79bd0ee538f42b7264a5d098af9a30959bf5"),
        ciphertext: &hex!("00be3b295899c455110a0ae833140c4d"),
        tag: &hex!("d054e3997c0085e87055b79829ec3629"),
    },
    TestVector {
        key: &hex!("2503b909a569f618f7eb186e4c4b81dbfe974c553e2a16a29aea6846293e1a51"),
        nonce: &hex!("e4fa3dc131a910c75f61a38b"),
        plaintext: &hex!("188d542f8a815695c48c3a882158958c"),
        aad: &hex!("f80edf9b51f8fd66f57ce9af5967ec028245eb6e"),
        ciphertext: &hex!("4d39b5494ca12b770099a8eb0c178aca"),
        tag: &hex!("adda54ad0c7f848c1c72758406b49355"),
    },
    TestVector {
        key: &hex!("6c8f34f14569f625aad7b232f59fa8b187ab24fadcdbaf7d8eb45da8f914e673"),
        nonce: &hex!("6e2f886dd97be0e4c5bd488b"),
        plaintext: &hex!("ac8aa71cfbf1e968ef5515531576e314"),
        aad: &hex!("772ec23e49dbe1d923b1018fc2bef4b579e46241"),
        ciphertext: &hex!("cb0ce70345e950b429e710c47d9c8d9b"),
        tag: &hex!("9dceea98c438b1d9c154e5386180966d"),
    },
    TestVector {
        key: &hex!("182fe560614e1c6adfd1566ac44856df723dcb7e171a7c5796b6d3f83ef3d233"),
        nonce: &hex!("8484abca6877a8622bfd2e3c"),
        plaintext: &hex!("92ca46b40f2c75755a28943a68a8d81c"),
        aad: &hex!("2618c0f7fe97772a0c97638cca238a967987c5e5"),
        ciphertext: &hex!("ed1941b330f4275d05899f8677d73637"),
        tag: &hex!("3fe93f1f5ffa4844963de1dc964d1996"),
    },
    TestVector {
        key: &hex!("65a290b2fabe7cd5fb2f6d627e9f1f79c2c714bffb4fb86e9df3e5eab28320ed"),
        nonce: &hex!("5a5ed4d5592a189f0737cf47"),
        plaintext: &hex!("662dda0f9c8f92bc906e90288100501c"),
        aad: &hex!("ad1c7f7a7fb7f8fef4819c1dd1a67e007c99a87b"),
        ciphertext: &hex!("8eb7cb5f0418da43f7e051c588776186"),
        tag: &hex!("2b15399ee23690bbf5252fb26a01ae34"),
    },
    TestVector {
        key: &hex!("7b720d31cd62966dd4d002c9ea41bcfc419e6d285dfab0023ba21b34e754cb2f"),
        nonce: &hex!("e1fb1f9229b451b72f89c333"),
        plaintext: &hex!("1aa2948ed804f24e5d783b1bc959e086"),
        aad: &hex!("7fdae42d0cf6a13873d3092c41dd3a19a9ea90f9"),
        ciphertext: &hex!("8631d3c6b6647866b868421b6a3a548a"),
        tag: &hex!("a31febbe169d8d6f391a5e60ef6243a0"),
    },
    TestVector {
        key: &hex!("a2aec8f3438ab4d6d9ae566a2cf9101ad3a3cc20f83674c2e208e8ca5abac2bb"),
        nonce: &hex!("815c020686c52ae5ddc81680"),
        plaintext: &hex!("a5ccf8b4eac22f0e1aac10b8d62cdc69"),
        aad: &hex!("86120ce3aa81445a86d971fdb7b3b33c07b25bd6"),
        ciphertext: &hex!("364c9ade7097e75f99187e5571ec2e52"),
        tag: &hex!("64c322ae7a8dbf3d2407b12601e50942"),
    },
    TestVector {
        key: &hex!("e5104cfcbfa30e56915d9cf79efcf064a1d4ce1919b8c20de47eab0c106d67c1"),
        nonce: &hex!("d1a5ec793597745c7a31b605"),
        plaintext: &hex!("7b6b303381441f3fdf9a0cf79ee2e9e0"),
        aad: &hex!("9931678430ff3aa765b871b703dfcc43fb1b8594"),
        ciphertext: &hex!("425d48a76001bed9da270636be1f770b"),
        tag: &hex!("76ff43a157a6748250a3fdee7446ed22"),
    },
    TestVector {
        key: &hex!("f461d1b75a72d942aa096384dc20cf8514a9ad9a9720660add3f318284ca3014"),
        nonce: &hex!("d0495f25874e5714a1149e94"),
        plaintext: &hex!("d9e4b967fdca8c8bae838a5da95d7cce"),
        aad: &hex!("1133f372e3db22456e7ea92f29dff7f1d92864d3"),
        ciphertext: &hex!("1df711e6fbcba22b0564c6e36051a3f7"),
        tag: &hex!("f0563b7494d5159289b644afc4e8e397"),
    },
    TestVector {
        key: &hex!("a9a98ef5076ceb45c4b60a93aeba102507f977bc9b70ded1ad7d422108cdaa65"),
        nonce: &hex!("54a1bc67e3a8a3e44deec232"),
        plaintext: &hex!("ede93dd1eaa7c9859a0f709f86a48776"),
        aad: &hex!("10cfef05e2cd1edd30db5c028bd936a03df03bdc"),
        ciphertext: &hex!("3d3b61f553ab59a9f093cac45afa5ac0"),
        tag: &hex!("7814cfc873b3398d997d8bb38ead58ef"),
    },
    TestVector {
        key: &hex!("d9e17c9882600dd4d2edbeae9a224d8588ff5aa210bd902d1080a6911010c5c5"),
        nonce: &hex!("817f3501e977a45a9e110fd4"),
        plaintext: &hex!("d74d968ea80121aea0d7a2a45cd5388c"),
        aad: &hex!("d216284811321b7591528f0af5a3f2768429e4e8"),
        ciphertext: &hex!("1587c8b00e2c197f32a21019feeee99a"),
        tag: &hex!("63ea43c03d00f8ae5724589cb6f64480"),
    },
    TestVector {
        key: &hex!("ec251b45cb70259846db530aff11b63be00a951827020e9d746659bef2b1fd6f"),
        nonce: &hex!("e41652e57b624abd84fe173a"),
        plaintext: &hex!("75023f51ba81b680b44ea352c43f700c"),
        aad: &hex!("92dd2b00b9dc6c613011e5dee477e10a6e52389c"),
        ciphertext: &hex!("29274599a95d63f054ae0c9b9df3e68d"),
        tag: &hex!("eb19983b9f90a0e9f556213d7c4df0f9"),
    },
    TestVector {
        key: &hex!("61f71fdbe29f56bb0fdf8a9da80cef695c969a2776a88e62cb3d39fca47b18e3"),
        nonce: &hex!("77f1d75ab0e3a0ed9bf2b981"),
        plaintext: &hex!("110a5c09703482ef1343396d0c3852d3"),
        aad: &hex!("c882691811d3de6c927d1c9f2a0f15f782d55c21"),
        ciphertext: &hex!("7e9daa4983283facd29a93037eb70bb0"),
        tag: &hex!("244930965913ebe0fa7a0eb547b159fb"),
    },
    TestVector {
        key: &hex!("e4fed339c7b0cd267305d11ab0d5c3273632e8872d35bdc367a1363438239a35"),
        nonce: &hex!("0365882cf75432cfd23cbd42"),
        plaintext: &hex!("fff39a087de39a03919fbd2f2fa5f513"),
        aad: &hex!(
            "8a97d2af5d41160ac2ff7dd8ba098e7aa4d618f0f455957d6a6d0801796747ba57c32dfbaaaf15176528fe3a0e4550c9"
        ),
        ciphertext: &hex!("8d9e68f03f7e5f4a0ffaa7650d026d08"),
        tag: &hex!("3554542c478c0635285a61d1b51f6afa"),
    },
    TestVector {
        key: &hex!("bd93c7bfc850b33c86484e04859ed374beaee9d613bdca6f072d1d182aeebd04"),
        nonce: &hex!("6414c7749effb9af7e5c4762"),
        plaintext: &hex!("b6de1699931f2252efc98d491d22ee12"),
        aad: &hex!(
            "76f43d5664c7ac1b4de43f2e2c4bc71f6918e0762f40e5dd5597ef4ff215855a4fd26d3ea6ccbd4e10789948fa692433"
        ),
        ciphertext: &hex!("a6c7e52f2018b823506e48064ffe6ee4"),
        tag: &hex!("175e653c9036f66835f10cf1c82d1741"),
    },
    TestVector {
        key: &hex!("df0125a826c7fe49243d89cbdd7562aafd2103fa2783cf901976b5f5d481cdcb"),
        nonce: &hex!("f63c1461b2964929d035d9bf"),
        plaintext: &hex!("cc27ff68f981e4d6fb1918427c3d6b9e"),
        aad: &hex!(
            "0bf602ec47593e44ac1b88244455fa04359e338057b0a0ba057cb506d546d4d6d8538640fe7dd3d5864bd33b5a33d768"
        ),
        ciphertext: &hex!("b8fa150af93078574ac7c4615f88647d"),
        tag: &hex!("4584553ac3ccdf8b0efae517652d3a18"),
    },
    TestVector {
        key: &hex!("d33ea320cec0e43dfc1e3d1d8ccca2dd7e30ad3ea18ad7141cc83645d18771ae"),
        nonce: &hex!("540009f321f41d00202e473b"),
        plaintext: &hex!("e56cdd522d526d8d0cd18131a19ee4fd"),
        aad: &hex!(
            "a41162e1fe875a81fbb5667f73c5d4cbbb9c3956002f7867047edec15bdcac1206e519ee9c238c371a38a485c710da60"
        ),
        ciphertext: &hex!("8b624b6f5483f42f36c85dc7cf3e9609"),
        tag: &hex!("2651e978d9eaa6c5f4db52391ac9bc7c"),
    },
    TestVector {
        key: &hex!("7f35f5979b23321e6449f0f5ef99f2e7b796d52d560cc77aabfb621dbf3a6530"),
        nonce: &hex!("cf0f6f3eed4cf374da714c77"),
        plaintext: &hex!("4e9f53affdb5b1e91bf423d29c54401a"),
        aad: &hex!(
            "a676d35d93e12bfe0603f6aef2c3dd892a9b1ad22d476c3509d313256d4e98e4dda4e46e93b54cf59c2b90608a8fb3ad"
        ),
        ciphertext: &hex!("1714d55ef83df2927ee95ff22f1d90e6"),
        tag: &hex!("4962a91d1071dd2c05934968d21eb43c"),
    },
    TestVector {
        key: &hex!("06ecc134993506cf539b1e797a519fe1d9f34321fe6a0b05f1936285c35c93a4"),
        nonce: &hex!("f2190861d1140bd080d79906"),
        plaintext: &hex!("519c1fc45a628ec16c515427796711f7"),
        aad: &hex!(
            "a04f2723c2521181437ad63f7910481d5de98f3e2561cec3a177bdbcb5048619738852e0fb212a3caa741a353e4e89a8"
        ),
        ciphertext: &hex!("b36c793224ce3bb1b54144398fbdedb6"),
        tag: &hex!("0030e6e84f6f8eb474ce8e071c2953dd"),
    },
    TestVector {
        key: &hex!("734fa8b423b91e0ecccc7f554480eef57a82423a9f92b28d464320fba405a71c"),
        nonce: &hex!("a6b5c78bb5791f4d121390ce"),
        plaintext: &hex!("b496a99b39e0e94bb5829cfc3d7b3856"),
        aad: &hex!(
            "9ce25ff9b55dfa04e4271999a47cba8af8e83a390b090d1c4306b40ce8882624b662ff5867896396789295c19ec80d07"
        ),
        ciphertext: &hex!("904081a40484bb6454fc52cb6674e737"),
        tag: &hex!("6a0787cf3921a71c35b5054954527823"),
    },
    TestVector {
        key: &hex!("d106280b84f25b294f71c261f66a65c2efd9680e19f50316d237975052796392"),
        nonce: &hex!("cfc6aa2aeba468c66bf4553f"),
        plaintext: &hex!("57e937f8b9b814e965bb569fcf63aaac"),
        aad: &hex!(
            "012a43f9903a3808bf34fd6f77d831d9154205ded589964cae60d2e49c856b7a4100a55c8cd02f5e476f62e988dcbd2b"
        ),
        ciphertext: &hex!("c835f5d4fd30fe9b2edb4aff24803c60"),
        tag: &hex!("e88426bb4619807f18a9cc9839754777"),
    },
    TestVector {
        key: &hex!("81eb63bc47aba313d964a5335cfb039051520b3112fa54cab368e5243947d450"),
        nonce: &hex!("18cc5dd875753ff51cc6f441"),
        plaintext: &hex!("45f51399dff6a0dcd43f35256616d6be"),
        aad: &hex!(
            "24f766c56777312494245a4e6c7dbebbae4026e0907eadbc20a488982678161de7b924473c0a81ee59a0fa6905952b33"
        ),
        ciphertext: &hex!("a2fc7b0784ec4233142f9cde12ab9e98"),
        tag: &hex!("4e60b8561cacfe7133740cd2bddefaa0"),
    },
    TestVector {
        key: &hex!("0a997863786a4e97332224ed484ffca508b166f0603687200d99fd6accd45d83"),
        nonce: &hex!("7a9acabd4b8d3e1036293a07"),
        plaintext: &hex!("9d2c9ff39f57c96ecce287c68c5cd6eb"),
        aad: &hex!(
            "525fc5ac7fe93c183a3ef7c75e3fbd52dce956855aff385966f4d79966bdb3ec2019c466584d21bfee74511a77d82adb"
        ),
        ciphertext: &hex!("238441c65b2a1c41b302da0f52d40770"),
        tag: &hex!("c351d93ab9491cdfb7fa15e7a251de22"),
    },
    TestVector {
        key: &hex!("acbfeb7c595b704960c1097e93d3906534c23444c8acc1f8e969ce6c3fe8a46b"),
        nonce: &hex!("28922ecac3013806c11660e6"),
        plaintext: &hex!("e0d8c52d60c6ed6980abd4348f3f96f1"),
        aad: &hex!(
            "b1fe886107013ebdeb19315a9d096ed81803951a508f56f68202a7df00bebae0742dd1128c200952a049ef0cd7cfe4e6"
        ),
        ciphertext: &hex!("56fe1cf2c1d193b9b33badbf846f52cc"),
        tag: &hex!("1cb4c14f50a54a64813ffc810f31f9f8"),
    },
    TestVector {
        key: &hex!("f6e768475c33269596da1f5a5a38547a885006bebb9134e21274d8456e9f5529"),
        nonce: &hex!("3579e5ac51d1f1b82ea352ca"),
        plaintext: &hex!("0aa481f856f8b96547672e5ae5370f9e"),
        aad: &hex!(
            "6929b6053ba148304366164f79b1b9f592c9cb9bce65094cec5cb8b0fc63e20d86b17c8bf5a7b089a63c5eac1824ee93"
        ),
        ciphertext: &hex!("b2f4edf5f0b0bfc590fead6239b0f2fb"),
        tag: &hex!("2540ceb5ef247c95d63df84c46468533"),
    },
    TestVector {
        key: &hex!("2ca76112300bed65b87ba6ec887cd514f4633c1c96565fec8e3e69ae2ba88401"),
        nonce: &hex!("964864510a8c957dcfb97d2f"),
        plaintext: &hex!("0aff24b4c5aa45b81ce08ec2439be446"),
        aad: &hex!(
            "5aebdfd153a18763f36ecc9e8e9a01cb7b3f21e435b35b0da937c67e87c9ec058d08060a95e1eda0a5ab6546cca45094"
        ),
        ciphertext: &hex!("03da1f5a1403dbdd9f75a26113608ec0"),
        tag: &hex!("a1c215d0c552a6061aa2b60afc3667a6"),
    },
    TestVector {
        key: &hex!("c0ff018b6c337dde685c8279cf6de59d7ce4b288032b819e074b671e72abbc91"),
        nonce: &hex!("f12e6b1e85f87ef4c9ccbb7b"),
        plaintext: &hex!("f7512bbfa2d40d14be71b70f70701c99"),
        aad: &hex!(
            "0577e8d28c0e9e5cde3c8b2a1a2aa8e2fc3ec8e96768405fcfbd623be7fc4e2e395c59b5b3a8ea117ef211320bc1f857"
        ),
        ciphertext: &hex!("0187b4c2d52486b4417e5a013d553e5e"),
        tag: &hex!("dba451e7339be8ebed3ea9683d1b4552"),
    },
    TestVector {
        key: &hex!("d90c6948ac2353867e943069196a2c4d0c4d51e34e2505661b1d76f3e5f17ac5"),
        nonce: &hex!("07e5623f474e2f0fe9f4c7d2"),
        plaintext: &hex!("8a9fb1b384c0d1728099a4f7cb002f07"),
        aad: &hex!(
            "0de97574ae1bc6d3ef06c6ce03513ca47dff4728803e0aacc50564ee32b775fd535f5c8c30186550d99bff6f384af2dd"
        ),
        ciphertext: &hex!("4234a3a9fb199c3b293357983e8ac30b"),
        tag: &hex!("d51e6f071dbab126f5fc9732967108ef"),
    },
    TestVector {
        key: &hex!("80d755e24d129e68a5259ec2cf618e39317074a83c8961d3768ceb2ed8d5c3d7"),
        nonce: &hex!("7598c07ba7b16cd12cf50813"),
        plaintext: &hex!("5e7fd1298c4f15aa0f1c1e47217aa7a9"),
        aad: &hex!(
            "0e94f4c48fd0c9690c853ad2a5e197c5de262137b69ed0cdfa28d8d12413e4ffff15374e1cccb0423e8ed829a954a335ed705a272ad7f9abd1057c849bb0d54b768e9d79879ec552461cc04adb6ca0040c5dd5bc733d21a93702"
        ),
        ciphertext: &hex!("5762a38cf3f2fdf3645d2f6696a7eead"),
        tag: &hex!("8a6708e69468915c5367573924fe1ae3"),
    },
    TestVector {
        key: &hex!("dda7977efa1be95a0e41ed8bcd2aa648621945c95a9e28b63919e1d92d269fc3"),
        nonce: &hex!("053f6e1be42af8894a6e86a0"),
        plaintext: &hex!("6fa9b08176e9963927afba1e5f969a42"),
        aad: &hex!(
            "cb5114a001989339657427eb88329d6ce9c69694dc91a69b7557d62184e57832ec76d162fc9c47490bb3d78e5899445cecf85d36cb1f07fed5a3d82aaf7e9590f3ed74ad13b13c8adbfc7f29d7b151448d6f29d11d0bd3d03b76"
        ),
        ciphertext: &hex!("d4adbff3ec8edade29b9a1b748c31b54"),
        tag: &hex!("3b331733c753858c22d309ceb0f9488c"),
    },
    TestVector {
        key: &hex!("d7da934ad057dc06bd1ec234fcc4efdc5119037a440b5827de25915f22dd47e5"),
        nonce: &hex!("1b54c4ea37d2395ef70dcc72"),
        plaintext: &hex!("86d5567658361198348207ede7a46da6"),
        aad: &hex!(
            "735de4596a80e64e38a12ab24ef73881d6ed3b533cb2c101025c3615acd2114150feeca84ade4e563bc4a300eb4a0cd97a184a293f0ac063e4f3c61e7fcdb331bcc6459fafaf0e2dda881f34eb717f4ee8c4b6890d3ef59721f3"
        ),
        ciphertext: &hex!("70a1c1d7c200ba5ae1b6f29917bb19f2"),
        tag: &hex!("a25d51cccb198bed33de0b98df249c2d"),
    },
    TestVector {
        key: &hex!("930ebb4b9b9c35094be374cc0b700c437b3c46b45d489a716c30f93cd5f986c9"),
        nonce: &hex!("7a21e5febd82ec9b97bfbe83"),
        plaintext: &hex!("980086665d08a365f6bbe20ae51116f7"),
        aad: &hex!(
            "9f2ed5f6cf9e2d6505d3c99a8f81a7dfc5658dd085eba966c8b3206230973a086ec36fe948573baee108fca941bce53dad73180877cd497976209c1adf8a9861f0215560df064caf0ef2f99445c11816f5b8deeafedd682b5fb2"
        ),
        ciphertext: &hex!("05baaefdeb0c33674a8064a2e9951aaf"),
        tag: &hex!("2ec7efd2564d4e09a6ab852f3af49939"),
    },
    TestVector {
        key: &hex!("70213d8949a65f463d13206071fab1b4c6b614fd3cee0d340d2d806de6714a93"),
        nonce: &hex!("f8529d3e4f155cbb1ffb3d0a"),
        plaintext: &hex!("47d47a5fd32a2a416f921cc7f00c0f81"),
        aad: &hex!(
            "112360db39b867dabaaa1d777bd881df2104b69fba15a4f37a832f5da38ad8a8c7c46db93e5b4eadf8b9a5a75508ad1457994c133c5ac85509eedfb13b90a2cf6c56a3c778582939362008608b08f9c4866a0e38744572114598"
        ),
        ciphertext: &hex!("b220b69bd851a17fbc5b725fb912f11e"),
        tag: &hex!("4c3436943d58501c0826ae5827bc063e"),
    },
    TestVector {
        key: &hex!("7a5834230ebbbf616630f2edb3ad4320182433c0546ac1e34bc9fd046e4a0ed9"),
        nonce: &hex!("d27dd6212b6defdcbbc701bb"),
        plaintext: &hex!("b4def1251427ade064a9614e353dda3f"),
        aad: &hex!(
            "3bc12f3bb88ea4f8a2184959bb9cd68911a78458b27e9b528ccecafe7f13f303dc714722875f26b136d18a3acfe82b53ad5e13c71f3f6db4b0fd59fffd9cd4422c73f2c31ac97010e5edf5950dc908e8df3d7e1cbf7c34a8521e"
        ),
        ciphertext: &hex!("88f94965b4350750e11a2dc139ccaef1"),
        tag: &hex!("8a61f0166e70c9bfdd198403e53a68a5"),
    },
    TestVector {
        key: &hex!("c3f10586f246aacadcce3701441770c03cfec940afe1908c4c537df4e01c50a0"),
        nonce: &hex!("4f52faa1fa67a0e5f4196452"),
        plaintext: &hex!("79d97ea3a2edd65045821ea745a44742"),
        aad: &hex!(
            "46f9a22b4e52e1526513a952dbee3b91f69595501e0177d50ff364638588c08d92fab8c58a969bdcc84c468d8498c4f06392b99ed5e0c484507fc48dc18d87c40e2ed848b43150be9d36f14cf2cef1310ba4a745adcc7bdc41f6"
        ),
        ciphertext: &hex!("560cf716e56190e9397c2f103629eb1f"),
        tag: &hex!("ff7c9124879644e80555687d273c55d8"),
    },
    TestVector {
        key: &hex!("ad70ebcf889e88b867ded0e4838ca66d6991499046a5671d99e91ed463ae78b1"),
        nonce: &hex!("561e13b335718fcbee364100"),
        plaintext: &hex!("82d5568872a4cef12238c0feb14f0fb4"),
        aad: &hex!(
            "e037bd7306eec185b9cb4e3bf295232da19005957086d62e6fb342284f05feaa0e81d6c95071e7e4d7b6aad7b00f7e7863dd0fc16303a8304bb8855305f28067f4be71eed95ff90e046382116229f0fd3d2c3ef2e87e0d0e7950"
        ),
        ciphertext: &hex!("771c6d091f8190ddbdb8886d9ce2ebd5"),
        tag: &hex!("5009abd1ebeb26dab852346ea6d8aee3"),
    },
    TestVector {
        key: &hex!("a452fa24b381e7165ee90f3371c2b0db2176f848a0354c78e92f2f1f89bbc511"),
        nonce: &hex!("4bd904dfe18241eb5455d912"),
        plaintext: &hex!("3f43df23ea940f3680a4b679b56db579"),
        aad: &hex!(
            "64f1a9d21deb183cff84f1aef5be83dbfc72e275f229eb5d59ace143605e8901dfa8f4724be24c86b5429bc84b629971fe1f9663b7537427b45dfb67d5f04506df4ee2c33d7f15af9f6e86058b131b7e6042b43a55bf6915f048"
        ),
        ciphertext: &hex!("c054974c4562f8536aef2734f10e09fc"),
        tag: &hex!("2c5cafaf7b1f7581c5ec13080994e33c"),
    },
    TestVector {
        key: &hex!("209ea3c4dd0420a4d63dbb72099a0202c9b0709f3b1221565f890511eef8005b"),
        nonce: &hex!("43775083e4008816129f5d40"),
        plaintext: &hex!("b4967f8c4fb1b34b6ff43a22d34fae5c"),
        aad: &hex!(
            "9abc653a2347fc6e5a8cb9bdc251dff7c56109797c387494c0ed55570330961eb5b11087603e08ad293d0dd55571008e62d1163f67cf829e28d27beba65553bd11d8838f8a7a5f1fe05500befbaf97839801e99ecf998882c707"
        ),
        ciphertext: &hex!("a8d22a6e25232938d3f8600a66be80da"),
        tag: &hex!("2ef93cc03c17bbfb6626144697fd2422"),
    },
    TestVector {
        key: &hex!("dabd63ac5274b26842c2695c9850d7accc1693ee2aeee1e2e1338bbbc5b80f87"),
        nonce: &hex!("fd6790d620f12870b1d99b31"),
        plaintext: &hex!("4a28048f5683679a557630a661f030e2"),
        aad: &hex!(
            "e4a06b9b205a7faadb21dc7fea8a0de0e013d717b61b24ec42f81afc8cdbc055573e971375da2fa5103a091317eab13b6a110ea211af257feabf52abafec23fd5b114b013d5c052199020573f8b7b7ae6958f733e87efa0426c2"
        ),
        ciphertext: &hex!("196d0345df259b47665bc233b798ebba"),
        tag: &hex!("b0729d8b427ad048a7396cedf2257338"),
    },
    TestVector {
        key: &hex!("b238df5e52e649d4b0a05e53020ac59e7d5bf49b8d04f8c30c356ed62dba9ed1"),
        nonce: &hex!("f153f093c9a3479f999eda04"),
        plaintext: &hex!("d48e779766afa73d7e04fc6fc3fa825e"),
        aad: &hex!(
            "45b5df0c15140e5ce7a19f4e02834e6027971e3e0e719626c29081a6301e95c71214345afac1908bb75ff2d3281261e6c5f41dc4e4796f054174a64f8e177f3f33321edfbd263e204135699428a09f34eb344211bfb9fac9afba"
        ),
        ciphertext: &hex!("b1989eb510843d8f35205dc3f949522f"),
        tag: &hex!("616089990729228f673099514824d9b4"),
    },
    TestVector {
        key: &hex!("f3dc2456d3b8947591a2d82b7319226b0f346cd4361bcc13b56da43e072a2774"),
        nonce: &hex!("7a8acb5a84d7d01e3c00499e"),
        plaintext: &hex!("ad075da908231ff9aae30daa6b847143"),
        aad: &hex!(
            "5e6be069effee27d34a8087c0d193f9f13e6440dc9fabfe24f6c867f831d06789d0dce92b2e3ff3ab9fe14202a8b42f384c25e3f3753dd503ec907a9b877f1707d64e4ac42909a7dee00c87c4a09d04de331515460ed101f5187"
        ),
        ciphertext: &hex!("9f224f2a1a1fbaade8b87b748971c0ac"),
        tag: &hex!("cb5089d9dfaebf98e4b36ebc5f9a1a50"),
    },
    TestVector {
        key: &hex!("f5a56b69a1562c77e8edebc327a20295c2eba7d406d899a622c53539626c9d72"),
        nonce: &hex!("a395b8aca4508a6a5f3cb4d8"),
        plaintext: &hex!("7de4638701bd2b600d7f8d26da7a75bc"),
        aad: &hex!(
            "2e4fca2b163e4403971716015386cd81bdd1e57f00f2936da408098341011f2644a38ddad799f70eaa54f6e430d4853ff2b9c44a35123670879a83120bd555c76b95b70de0c8054f9d08539a5795e70a2446d7b9fab3f7887c6b"
        ),
        ciphertext: &hex!("6508be2698ba9889b4e445b99190a5c5"),
        tag: &hex!("3394106f257c2e15c815430f60bc24ba"),
    },
    TestVector {
        key: &hex!("376371a780947256c52f07d80bb25a4d7e919ca8bd693b1a0ccbca748d2ce620"),
        nonce: &hex!("27d7170f6f70f2fc40dfca78"),
        plaintext: &hex!("7a279f9f8568b7c307490549b259226c"),
        aad: &hex!(
            "272c3559398ad774fa4b6895afc92870b2b92d310fa0debf0b7960e1fe38bfda64acd2fef26d6b177d8ab11d8afceee77374c6c18ad405d5ae323ad65fb6b04f0c809319133712f47636c5e042f15ed02f37ee7a10c643d7b178"
        ),
        ciphertext: &hex!("32284379d8c40ec18ee5774085d7d870"),
        tag: &hex!("dcdee1a757f9758c944d296b1dabe7b2"),
    },
    TestVector {
        key: &hex!("82c4f12eeec3b2d3d157b0f992d292b237478d2cecc1d5f161389b97f999057a"),
        nonce: &hex!("7b40b20f5f397177990ef2d1"),
        plaintext: &hex!("982a296ee1cd7086afad976945"),
        aad: b"",
        ciphertext: &hex!("ec8e05a0471d6b43a59ca5335f"),
        tag: &hex!("113ddeafc62373cac2f5951bb9165249"),
    },
    TestVector {
        key: &hex!("db4340af2f835a6c6d7ea0ca9d83ca81ba02c29b7410f221cb6071114e393240"),
        nonce: &hex!("40e438357dd80a85cac3349e"),
        plaintext: &hex!("8ddb3397bd42853193cb0f80c9"),
        aad: b"",
        ciphertext: &hex!("b694118c85c41abf69e229cb0f"),
        tag: &hex!("c07f1b8aafbd152f697eb67f2a85fe45"),
    },
    TestVector {
        key: &hex!("acad4a3588a7c5ec67832baee242b007c8f42ed7425d5a7e57b1070b7be2677e"),
        nonce: &hex!("b11704ba368abadf8b0c2b98"),
        plaintext: &hex!("2656b5fbec8a3666cad5f460b7"),
        aad: b"",
        ciphertext: &hex!("35c7114cabe39203df19413a99"),
        tag: &hex!("16f4c7e5becf00db1223476a14c43ebc"),
    },
    TestVector {
        key: &hex!("e5a0eb92cc2b064e1bc80891faf1fab5e9a17a9c3a984e25416720e30e6c2b21"),
        nonce: &hex!("4742357c335913153ff0eb0f"),
        plaintext: &hex!("8499893e16b0ba8b007d54665a"),
        aad: b"",
        ciphertext: &hex!("eb8e6175f1fe38eb1acf95fd51"),
        tag: &hex!("88a8b74bb74fda553e91020a23deed45"),
    },
    TestVector {
        key: &hex!("e78c477053f5dae5c02941061d397bc38dda5de3c9c8660a19de66c56c57fd22"),
        nonce: &hex!("4f52c67c2bb748d192a5a4e2"),
        plaintext: &hex!("91593e21e1f883af5c32d9be07"),
        aad: b"",
        ciphertext: &hex!("e37fbc56b0af200a7aa1bbe34e"),
        tag: &hex!("29fe54eaaccf5e382601a15603c9f28c"),
    },
    TestVector {
        key: &hex!("d0b13482037639aa797471a52b60f353b42e0ed271daa4f38a9293191cb78b72"),
        nonce: &hex!("40fb7cae46adf3771bf3756a"),
        plaintext: &hex!("938f40ac8e0e3b956aac5e9184"),
        aad: b"",
        ciphertext: &hex!("7dca05a1abe81928ccfb2164dd"),
        tag: &hex!("5ea53ee170d9ab5f6cc047854e47cf60"),
    },
    TestVector {
        key: &hex!("46da5ec688feead76a1ddcd60befb45074a2ef2254d7be26abdfd84629dbbc32"),
        nonce: &hex!("9fb3b2b03925f476fc9a35f3"),
        plaintext: &hex!("a41adc9fb4e25a8adef1180ec8"),
        aad: b"",
        ciphertext: &hex!("f55d4cbe9b14cea051fe7a2477"),
        tag: &hex!("824753da0113d21186699dbb366c0589"),
    },
    TestVector {
        key: &hex!("de3adf89f2fe246c07b0ce035f4af73cf2f65e5034dcfecfe9d7690ae1bdbd96"),
        nonce: &hex!("a94aa4df0d8451644a5056c0"),
        plaintext: &hex!("96825f6d6301db14a8d78fc2f4"),
        aad: b"",
        ciphertext: &hex!("784c6c3c24a022637cbc907c48"),
        tag: &hex!("1eeaeddcdb4c72c4e8966950a319a4ef"),
    },
    TestVector {
        key: &hex!("03c362288883327f6289bc1824e1c329ce485e0ce0e8d3405245283cf0f2eae2"),
        nonce: &hex!("5de9f882c915c72729b2245c"),
        plaintext: &hex!("f5c1c8d41de01d9c08d9f47ece"),
        aad: b"",
        ciphertext: &hex!("61af621953a126a2d1de559e92"),
        tag: &hex!("fbdeb761238f2b70c5fb3dde0a7978f3"),
    },
    TestVector {
        key: &hex!("e9ead7c59100b768aa6367d80c04a49bcd19fa8cc2e158dc8edeec3ea39b657d"),
        nonce: &hex!("e81854665d2e0a97150fbab3"),
        plaintext: &hex!("f8ccf69c52a873695367a42940"),
        aad: b"",
        ciphertext: &hex!("af2a7199602ee9ed2020c7b4cd"),
        tag: &hex!("29715945ab1c034ecfcd91a466fc822e"),
    },
    TestVector {
        key: &hex!("bc3e5b0fe423205904c32f870b9adec9d736a1616624043e819533fa97ed9b79"),
        nonce: &hex!("335fe5180135673ce1a75144"),
        plaintext: &hex!("295df9665eef999204f92acf24"),
        aad: b"",
        ciphertext: &hex!("3ac2a8a1b505a84677adfdb396"),
        tag: &hex!("21f20aa0bb77d46d7290bc9c97a7a7bd"),
    },
    TestVector {
        key: &hex!("ce889c73e0d64e272aba4bf9777afc7ee6457ddc9626ad931708ed7530d71b99"),
        nonce: &hex!("fe61a6cda62fecd4e3b0c562"),
        plaintext: &hex!("e2ae40ba5b4103b1a3066c1b57"),
        aad: b"",
        ciphertext: &hex!("185aa3508a37e6712b28191ec2"),
        tag: &hex!("9ec1d567585aa467730cce92e536728e"),
    },
    TestVector {
        key: &hex!("41e0cb1aed2fe53e0b688acb042a0c710a3c3ae3205b07c0af5191073abdfba9"),
        nonce: &hex!("2f56e35216d88d34d08f6872"),
        plaintext: &hex!("6482df0e4150e73dac51dc3220"),
        aad: b"",
        ciphertext: &hex!("9cb09b9927dfbe0f228e0a4307"),
        tag: &hex!("fe7e87a596d63e2ab2aae46b64d466e8"),
    },
    TestVector {
        key: &hex!("52a7662954d525cb00602b1ff5e937d41065ac4b921e284ffac73c04cfd462a0"),
        nonce: &hex!("baffe73856ab1a47fb1feebf"),
        plaintext: &hex!("9d0b5ca712f97caa1875d3ad87"),
        aad: b"",
        ciphertext: &hex!("fd01165380aedd6be226a66af3"),
        tag: &hex!("35a492e39952c26456850b0172d723d1"),
    },
    TestVector {
        key: &hex!("c4badb9766986faeb888b1db33060a9cd1f02e1afe7aaaea072d905750cb7352"),
        nonce: &hex!("cc6966e9d81a298a561416d4"),
        plaintext: &hex!("de68fb51731b45e7c2c5063923"),
        aad: b"",
        ciphertext: &hex!("f5be41f2c8c32e01098d433057"),
        tag: &hex!("c82b1b012916ab6ed851d59829dad8ab"),
    },
    TestVector {
        key: &hex!("dad89d9be9bba138cdcf8752c45b579d7e27c3dbb40f53e771dd8cfd500aa2d5"),
        nonce: &hex!("cfb2aec82cfa6c7d89ee72ff"),
        plaintext: &hex!("b526ba1050177d05b0f72f8d67"),
        aad: &hex!("6e43784a91851a77667a02198e28dc32"),
        ciphertext: &hex!("8b29e66e924ecae84f6d8f7d68"),
        tag: &hex!("1e365805c8f28b2ed8a5cadfd9079158"),
    },
    TestVector {
        key: &hex!("0d35d3dbd99cd5e088caf686b1cead9defe0c6001463e92e6d9fcdc2b0dcbaf6"),
        nonce: &hex!("f9139eb9368d69ac48479d1f"),
        plaintext: &hex!("5e2103eb3e739298c9f5c6ba0e"),
        aad: &hex!("825cc713bb41c789c1ace0f2d0dd3377"),
        ciphertext: &hex!("8ff3870eec0176d9f0c6c1b1a2"),
        tag: &hex!("344234475538dc78c01f249f673e0862"),
    },
    TestVector {
        key: &hex!("d35d64f1872bdcb422228f0d63f8e48977ed68d143f648ae2cd852f944b0e6dd"),
        nonce: &hex!("0b2184aadbe8b515924dda5e"),
        plaintext: &hex!("c8f999aa1a08871d74db490cf3"),
        aad: &hex!("888f328d9e9eebbb9cb2704b5b880d66"),
        ciphertext: &hex!("ad0d5e7c1065a34b27a256d144"),
        tag: &hex!("8c8e7076950f7f2aeba62e1e761650d5"),
    },
    TestVector {
        key: &hex!("9484b7ce3c118a8a2d556c2f7ba41fca34f60c9ea1070171459c9e7487c9537e"),
        nonce: &hex!("87bc033522ae84d2abe863c5"),
        plaintext: &hex!("14d8004793190563825e273dda"),
        aad: &hex!("07ee18737b9bf8223979a01c59a90eb4"),
        ciphertext: &hex!("43034a2c57ccacc367796d766a"),
        tag: &hex!("4c981ca8b6e9e52092f5435e7ef55fbb"),
    },
    TestVector {
        key: &hex!("4f4539e4a80ec01a14d6bb1bae0010f8a8b3f2cd0ac01adf239a9b2b755f0614"),
        nonce: &hex!("2b6f00ce1570432bf52fdcac"),
        plaintext: &hex!("820cc9389e7e74ca1cbb5a5fe6"),
        aad: &hex!("0d72a13effe40544c57cc18005b998cb"),
        ciphertext: &hex!("99553fdf3e777e2a4b3b6a5538"),
        tag: &hex!("3cbf51640a3a93c3662c738e98fb36a2"),
    },
    TestVector {
        key: &hex!("2f5e93ee24a8cd2fc6d3765f12d2179ddb8397783e136af9e0ac75f16fca451e"),
        nonce: &hex!("0dc3c70a191f3722641fd701"),
        plaintext: &hex!("4e96463793cdeda403668c4aee"),
        aad: &hex!("ebab30cbcc99905354e4ee6f07c7db87"),
        ciphertext: &hex!("ab03f8ca7b1b150bdc26d4e691"),
        tag: &hex!("020546afff4290c4c8ef7fc38035ebfd"),
    },
    TestVector {
        key: &hex!("a902e15d06ef5ad334d0ec6502e936ee53ef3f3608f7708848b11cefa92983d1"),
        nonce: &hex!("b9f3e966efa43ab4aca1f2d8"),
        plaintext: &hex!("393ff3dfe51cd43543e4e29fcc"),
        aad: &hex!("2eaa35c00bf1cf8a81919bd04b43fd97"),
        ciphertext: &hex!("7e8928b450c622ac8efe29d5a0"),
        tag: &hex!("5a285de95990aef171629350bbcaf46e"),
    },
    TestVector {
        key: &hex!("96657976da7692004e271b594e8304f77db9c9e77859246bb30a16239ba76a53"),
        nonce: &hex!("79226100afea30644876e79a"),
        plaintext: &hex!("2b0833a065c3853ee27c8968d0"),
        aad: &hex!("ede7a9072a0086b9a1e55d900747cf76"),
        ciphertext: &hex!("19373168f1a4052a57c6b8146f"),
        tag: &hex!("debbf044325384b90a0c442d95455fb9"),
    },
    TestVector {
        key: &hex!("630ea13eb5f52378b976ba2662f824dc622920759a15d2e341c446b03ea7bd5c"),
        nonce: &hex!("0f9ebe47682f93d44c4db314"),
        plaintext: &hex!("5c734964878a4250a3bf61fdd6"),
        aad: &hex!("5ad8e9cffe622e9f35bdb185473868e5"),
        ciphertext: &hex!("67cb6d943340d002d3323fcc4e"),
        tag: &hex!("f5dc0f88f236560c4e2a6d6c15d3c0de"),
    },
    TestVector {
        key: &hex!("c64f8a3ac230dce61b53d7b584f2309384274d4b32d404bc0c491f129781e52d"),
        nonce: &hex!("7f4b3bcf763f9e2d08516a6d"),
        plaintext: &hex!("fe581128ae9832d27ec58bd7ac"),
        aad: &hex!("89ed6945547ee5998de1bb2d2f0bef1e"),
        ciphertext: &hex!("81d7a8fdaf42b5716b892199c9"),
        tag: &hex!("8183aaff4c0973fe56c02c2e0c7e4457"),
    },
    TestVector {
        key: &hex!("dd73670fb221f7ee185f5818065e22dda3780fc900fc02ef00232c661d7bffce"),
        nonce: &hex!("c33de65344cfbf228e1652bd"),
        plaintext: &hex!("ada4d98147b30e5a901229952a"),
        aad: &hex!("e1a5e52427f1c5b887575a6f2c445429"),
        ciphertext: &hex!("6ed4e4bd1f953d47c5288c48f4"),
        tag: &hex!("404e3a9b9f5ddab9ee169a7c7c2cf7af"),
    },
    TestVector {
        key: &hex!("f6c5d9562b7dbdd0bf628ddc9d660c27841b06a638f56601f408f23aa2f66f4e"),
        nonce: &hex!("67280bcb945ba6eda1c6c80a"),
        plaintext: &hex!("f4caead242d180fbd2e6d32d0c"),
        aad: &hex!("5b33716567b6c67b78ea5cd9349bcaaf"),
        ciphertext: &hex!("fdfa39517d89ea47e6ccb0f831"),
        tag: &hex!("91f9b540ca90e310a1f5c12c03d8c25e"),
    },
    TestVector {
        key: &hex!("ce1d242f13de7638b870e0aa85843ea43a9255a4fa4d32057347f38e0267daeb"),
        nonce: &hex!("86562be4621b4d5eb1983075"),
        plaintext: &hex!("d20e59a8ef1a7de9096c3e6746"),
        aad: &hex!("d48a9490a0b7deb023460608b7db79ce"),
        ciphertext: &hex!("35ce69fb15d01159c52266537c"),
        tag: &hex!("dc48f7b8d3feeeb26fcf63c0d2a889ec"),
    },
    TestVector {
        key: &hex!("512753cea7c8a6165f2ebbd3768cc7b951029bd527b126233cf0841aff7568c7"),
        nonce: &hex!("b79221802d8d97978041fe84"),
        plaintext: &hex!("c63d6c1006b615275c085730b1"),
        aad: &hex!("22fa0605b955a33468f3e60160b907f2"),
        ciphertext: &hex!("bdb5d7f24732bdba1d2a429108"),
        tag: &hex!("fca923d2941a6fd9d596b86c3afb0ad9"),
    },
    TestVector {
        key: &hex!("e7b18429e3edded2d992ca27afab99e438b8aff25fc8460201fabe08e7d48ec2"),
        nonce: &hex!("9db9b7320aaac68538e37bf7"),
        plaintext: &hex!("c4713bc67a59928eee50039901"),
        aad: &hex!("283e12a26e1646087b5b9d8c123dde1f"),
        ciphertext: &hex!("a5932f92bda107d28f2a8aaa74"),
        tag: &hex!("9a1357fd8ed21fe14d1ca2e597c3ef17"),
    },
    TestVector {
        key: &hex!("69b458f2644af9020463b40ee503cdf083d693815e2659051ae0d039e606a970"),
        nonce: &hex!("8d1da8ab5f91ccd09205944b"),
        plaintext: &hex!("f3e0e09224256bf21a83a5de8d"),
        aad: &hex!("036ad5e5494ef817a8af2f5828784a4bfedd1653"),
        ciphertext: &hex!("c0a62d77e6031bfdc6b13ae217"),
        tag: &hex!("a794a9aaee48cd92e47761bf1baff0af"),
    },
    TestVector {
        key: &hex!("97431e565e8370a4879de962746a2fd67eca868b1c8e51eece2c1f94f74af407"),
        nonce: &hex!("17fb63066e2726d282ecc610"),
        plaintext: &hex!("e21629cc973fbe40176e621d9d"),
        aad: &hex!("78e7374da7c77be5938de8dd76cf0308618306a9"),
        ciphertext: &hex!("80dbd469de480389ba6c2fca52"),
        tag: &hex!("4e284abb8b4f9f13c7497ae56df05fa5"),
    },
    TestVector {
        key: &hex!("2b14ad68f442f7f92a72c7ba909bcf995c827b439d39a02f77c9bf8f84ab04dc"),
        nonce: &hex!("4c847ea59f83d82b0ac0bc37"),
        plaintext: &hex!("b3c4b26ebbfc717f51e874587d"),
        aad: &hex!("8eb650f662be23191e88f1cd0422e57453090e21"),
        ciphertext: &hex!("3e288478688e60178920090814"),
        tag: &hex!("a928dc026986823062f37ec825c67b95"),
    },
    TestVector {
        key: &hex!("11f41bf7d4b9ac7b0035ce54481ed1502ff05cfae02ffba9e502f61bfe785351"),
        nonce: &hex!("06f5cf8c12c236e094c32014"),
        plaintext: &hex!("bee374a32293cad5e1b28419b3"),
        aad: &hex!("d15cbde6290b7723625c99ffa82a9c4c03ed214d"),
        ciphertext: &hex!("3f8122deb6dbe0ff596441203d"),
        tag: &hex!("60ef7f3723710b9ab744f8eea00267f7"),
    },
    TestVector {
        key: &hex!("18ca572da055a2ebb479be6d6d7164e78f592b159cdea76e9fe208062d7b3fa1"),
        nonce: &hex!("1b041e534ae20748262f3929"),
        plaintext: &hex!("cda2fa0015361ecf684c6ba7d1"),
        aad: &hex!("e8a925d7ce18dd456b071cb4c46655940efbe991"),
        ciphertext: &hex!("740d8d578e2e7522c31019f471"),
        tag: &hex!("f2eeb5af1bfedd10570a137fe2566c3f"),
    },
    TestVector {
        key: &hex!("0de2ac5bfec9e8a859c3b6b86dde0537029cdca2d0844bf3e1d98f370e199be1"),
        nonce: &hex!("1778e308e0221288f1eb4c5a"),
        plaintext: &hex!("575d93a3416763cbd371b5a671"),
        aad: &hex!("1362264f5655f71986aa788efd48f6fc13bb6ab4"),
        ciphertext: &hex!("8f8df7ca83bf876b63c78e2c9a"),
        tag: &hex!("16c74e315aab97efafbe95c9dcaa2d0c"),
    },
    TestVector {
        key: &hex!("b381535a085bc4808fa7a139c7204e8a87c7145dfc8f3900df1fa9a9844fab35"),
        nonce: &hex!("21ddc54d3c633f4a344a0e42"),
        plaintext: &hex!("e4d958cee583010bbfd3a53021"),
        aad: &hex!("7ac3ba600e08363ddb57c45a8670bb4abb869db0"),
        ciphertext: &hex!("c42c81a312759cdb032aafe852"),
        tag: &hex!("0c472591db3df8a7c67164591542dcc9"),
    },
    TestVector {
        key: &hex!("29f21e5029ea4964b96dc6f4c34b2df4cce02f2fcf0f168ffd470e7858e0a0ad"),
        nonce: &hex!("63a1c1ccc328280a90ff96fe"),
        plaintext: &hex!("dc12113764c13c21432ca1ba33"),
        aad: &hex!("454f447433f0948581956c4be1b19d932e89b492"),
        ciphertext: &hex!("1cb45aac5def93daef806b781e"),
        tag: &hex!("f4b0723c89607b66c392049ba042db63"),
    },
    TestVector {
        key: &hex!("2733d3aa52a9d70a9fbd6ce2364bb5f9004902aa5eeb17446e08f2bdcc41db15"),
        nonce: &hex!("196c4addb84a58beb3674a7a"),
        plaintext: &hex!("cbc50cafda2544bcd291e8a025"),
        aad: &hex!("c9826fe31f29b55b9d0f9da9795869a1a98befe5"),
        ciphertext: &hex!("7a89cc58ccb97ad3e54ca4a9c8"),
        tag: &hex!("3990d9aba210182996fdbd91c2ae4801"),
    },
    TestVector {
        key: &hex!("0c4b9005b407415c19672bcd0ebe169f66fe404f22529baf55568e0901e94922"),
        nonce: &hex!("e51381e959a1f5688c938576"),
        plaintext: &hex!("c6179bd3451d9299b727e8bd0a"),
        aad: &hex!("0b512faeb4da740dcc1e30d3c7ea61035e8570b7"),
        ciphertext: &hex!("4d3fe086c990f16020b4c5eed6"),
        tag: &hex!("9ff2297845814719f851ab0943117efb"),
    },
    TestVector {
        key: &hex!("fee442ba37c351ec094a48794216a51d208c6a5ba0e5bdb8f3c0f0dfc1e4ed63"),
        nonce: &hex!("a666f2f0d42214dbaa6a2658"),
        plaintext: &hex!("a2cf3ea0e43e435261cb663a3b"),
        aad: &hex!("7198c12810345403862c5374092cc79b669baecc"),
        ciphertext: &hex!("713d4050f8c7fd63c0c1bf2ad9"),
        tag: &hex!("250a35e2b45ba6b0fe24512f8213d8cb"),
    },
    TestVector {
        key: &hex!("77f754d0cf7dbdaf75cfe965ab131e8cd39087ee6d986dec4ad2ff08ebd7f14b"),
        nonce: &hex!("e28a14f3107ca190d824ed5f"),
        plaintext: &hex!("54a97a74889e55d8043451c796"),
        aad: &hex!("1decf0cbc50a9da6dad4a785a941e4b95ce5aaa8"),
        ciphertext: &hex!("eedbf8dd81eb19184589dcb157"),
        tag: &hex!("7749edd752fab7e50dbc3b0b47678bf6"),
    },
    TestVector {
        key: &hex!("0523f232001e68bd65a79837bbaf70ec2e20851301d8e12fddb5926acb2100cb"),
        nonce: &hex!("2bb8d5cb3ceb15107582e1fa"),
        plaintext: &hex!("6b4cdc9f9c5082d86a1d2e68fe"),
        aad: &hex!("1f55bba71cb63df431ef8832c77499ee3c502067"),
        ciphertext: &hex!("079fe90ef517ed2f614a3cd8ce"),
        tag: &hex!("539c30590a2527f1d52dfae92920794c"),
    },
    TestVector {
        key: &hex!("54c56ee869ebb112a408717eb40af6937fe51eb061b42277a10537e7db346b6a"),
        nonce: &hex!("5bfb63e2f3e5b2e1b4343480"),
        plaintext: &hex!("75f9496b8d0ca96ed3af02dcab"),
        aad: &hex!("740ab07b9c5de2afa37f0788ae5230535c18203d"),
        ciphertext: &hex!("827902e58c4c8b7af976f61842"),
        tag: &hex!("036ee6473c2138f2a2c2841438cb0edc"),
    },
    TestVector {
        key: &hex!("d968ffdbed6ffc259b4310e2e97e42d877ef5d86d2169928c51031983779a485"),
        nonce: &hex!("633d0d8d3613c83b40df99dd"),
        plaintext: &hex!("08cfc65fea9b07f0c01d29dfdf"),
        aad: &hex!("9aadc8d8975ec0a3f5c960ce72aaec8ef0b42034"),
        ciphertext: &hex!("7b450f162bdedc301b96a3ac36"),
        tag: &hex!("970d97344b1451f3f969aeb972d352e6"),
    },
    TestVector {
        key: &hex!("5f671466378f470ba5f5160e2209f3d95a48b7e560625d5a08654414de23aee2"),
        nonce: &hex!("6b3c08a663d04132243dd96c"),
        plaintext: &hex!("c428592d9f8a7f107ec4d0df05"),
        aad: &hex!(
            "12965559c31d538f937bda6eee9c93b0387318dc5d9496fb1c3a0b9b978dbfebff2a5823974ee9d679834dbe59f7ec51"
        ),
        ciphertext: &hex!("1d8d7fe4357080c817303ce19c"),
        tag: &hex!("e88d6b566fdc7b4fd62106bd2eb806ec"),
    },
    TestVector {
        key: &hex!("fbcc2e7faa4295080e40b141bef829ba9d34e0691231ad6c62b5109009d74b5e"),
        nonce: &hex!("7f35d9ec651c5b0966573e2f"),
        plaintext: &hex!("cdd251d449551fec080425d565"),
        aad: &hex!(
            "6330d16002a8fd51762043f2df06ecc9c535c96ebe33526d8faf767c2c2af3cd01f4e02fa102f15ce0236d9c9cef26de"
        ),
        ciphertext: &hex!("514c5523024dd4c7d59bd73b15"),
        tag: &hex!("d3a399843e5776aa348e3e5e56482fff"),
    },
    TestVector {
        key: &hex!("04ef660ec041f5c0c24209f959ccf1a2a7cdb0dba22b134ea9f75e6f1efdae4a"),
        nonce: &hex!("0f5f6fbca29358217c8a6b67"),
        plaintext: &hex!("0835b312191f30f931e65aa05f"),
        aad: &hex!(
            "505e205d13ec945391c7d6516af86255e82f38433f40404d4f1e42d23b33eb9e6dea5820dad60622d3a825fc8f01a5d2"
        ),
        ciphertext: &hex!("5ddc0f5963f0290c1a0fb65be7"),
        tag: &hex!("106d1f8d26abe4b4b1e590cd5d85e737"),
    },
    TestVector {
        key: &hex!("42d3ff74284395fb9db9b8c7a444fa400f7fc6b985a7fec2478667c7f17cf3ba"),
        nonce: &hex!("89230fbed59d1226a093ad28"),
        plaintext: &hex!("d8339e3618ba57a243a27c85d6"),
        aad: &hex!(
            "60342f97310446266b2e47b18e008979d07fc181151ac0939b495e7f31de1d0e74042532840ab91686efd7a402d27a94"
        ),
        ciphertext: &hex!("9bb6fa36fa167016109d521ac0"),
        tag: &hex!("600909ef32ca62951ecbdc811caa7778"),
    },
    TestVector {
        key: &hex!("e115c6468606a5f9b8e9a7c220d7d7684d686c9210a669770b6e4bf24447cd17"),
        nonce: &hex!("029c7c9ee2d3ab26843e8b41"),
        plaintext: &hex!("7abf84842f9867cfc5eabc7032"),
        aad: &hex!(
            "1befd9f97f99fc096deafde5e158ac86716c0ba32454988fe48ba4737684361849a221c03fc0948cb25b5f29d6a0cb2a"
        ),
        ciphertext: &hex!("851c7047fb09646fbddb824531"),
        tag: &hex!("d0ac4110c8d768f0a804ecda387cfa30"),
    },
    TestVector {
        key: &hex!("56552f0cef34673a4c958ff55ad0b32c6ababa06cb3ae90178ab1c9a1f29c0e5"),
        nonce: &hex!("b34d24935407e8592247ffff"),
        plaintext: &hex!("dbd6cc358b28ab66a69f5238d4"),
        aad: &hex!(
            "b199437da189486a8fd1c2fa1fe3ebbb116f0ef41415bb7c8065272fb0b2fe8edca9cd0d4255d467e77f2834be557474"
        ),
        ciphertext: &hex!("76dc8d035e5ca4001e4e3fcb18"),
        tag: &hex!("49c01f735da1131cd42b01b746fd38de"),
    },
    TestVector {
        key: &hex!("d4f405ba556e6fe74b7e6dbdd7a8eae36376d1ca7a98d567d108729aeae5c326"),
        nonce: &hex!("df6637c98a6592843e0b81ef"),
        plaintext: &hex!("abe87641e9a5169f90179d3099"),
        aad: &hex!(
            "a5328cbabdfe6c3c1d4f5152189072dade71e2bacd857d3ce37ee9e3161eb0f20de5a29b7999fd9c7c60cdc03751bd1b"
        ),
        ciphertext: &hex!("06f9cf9677745e78c6c02bf06b"),
        tag: &hex!("5a3a76da0703c24a9588afb2ac1a9e13"),
    },
    TestVector {
        key: &hex!("4f667f65ea4569264456e25de498579036d6a604c18baf770bb626d8a1c68e4f"),
        nonce: &hex!("43e27d275abefdd45137c8ff"),
        plaintext: &hex!("eaa2498ce27e5658489381b6ec"),
        aad: &hex!(
            "264b807b4631d7c87ee9f1507082f5af9218f531b4630141f3c94939aa7cf81c71ea540783995560bf7e6e02d196227f"
        ),
        ciphertext: &hex!("bac018bf2e7090e7f217ab3365"),
        tag: &hex!("13e5a16a9ce7a88cda640de2c4fdc07e"),
    },
    TestVector {
        key: &hex!("f5624a166759ef0b8168af6565649f7797fa92476e008c407458101e75831312"),
        nonce: &hex!("521ca79ffc8930349abfc052"),
        plaintext: &hex!("1fab3def2ea13e815f8746093b"),
        aad: &hex!(
            "6e2771ecd637361cb6b947148910f7d9206d6af176c510bb5dd5bc9b97ac015fb05537affbc1756625715374172fb456"
        ),
        ciphertext: &hex!("ca72ff15a7eb62a2839bcf0c43"),
        tag: &hex!("475fff6d9e2382583c9614020844b92a"),
    },
    TestVector {
        key: &hex!("ac1383a3c783d3d0667e944cbe1a6159647b96afa922557eb1cb6407546b98ca"),
        nonce: &hex!("70366112dbe1bd905b900e3a"),
        plaintext: &hex!("b8dd871f9d866867efbe551c3b"),
        aad: &hex!(
            "b7c1865927737bee802415277cf1a25b7380774a9d27b6a3253f077d36e9c4142df2bbbf3c03414ac09161626ce9367c"
        ),
        ciphertext: &hex!("ba181874380841791f64881534"),
        tag: &hex!("c5641edf42c446873372bbbde1146642"),
    },
    TestVector {
        key: &hex!("f37499d9b6ad2e7618e30a23082673008f3ae1938b9397c02a4da2453fb7e403"),
        nonce: &hex!("18e112ea6a998d6f9705f7e0"),
        plaintext: &hex!("31560b2114a248ffe0696fa130"),
        aad: &hex!(
            "736f1a71fb259f46c6519bb87451f238f47d80c74a016604499b02568f1c7bedf70f9597d7b62c1698c4f2631f4e9706"
        ),
        ciphertext: &hex!("0163f558be0142ebabde29a7bc"),
        tag: &hex!("45579ce07ee64cdac3a7a42109ff44e7"),
    },
    TestVector {
        key: &hex!("50b7f5118ef7ee22b107d93ceab9881ef9658931e80385d1ae92501b95e47d62"),
        nonce: &hex!("d5113665039169978b7dc4db"),
        plaintext: &hex!("9ba4cd5e600277f4c786ce827e"),
        aad: &hex!(
            "68ff6c63e94cb7dd2b8413662a56c88dc130b79b8b2e2388c1089b61fa51ea37819109b5ef64da1250f5d6b5d74cc392"
        ),
        ciphertext: &hex!("67842199482b28be56f7570d11"),
        tag: &hex!("79e03841843fe32337b7c7409a2153bc"),
    },
    TestVector {
        key: &hex!("d396941c9c59e6a7bc7d71bd56daf6eabe4bfb943151cdb9895103384b8f38b4"),
        nonce: &hex!("f408f8c21f3825d7a87643ed"),
        plaintext: &hex!("dc8ad6a50812b25f1b0af70bee"),
        aad: &hex!(
            "947bd9a904e03fdd2c91d038d26d48ac6e32afcad908eacd42a25f6240964656d5a493242d3f8a19119a4cd9957d9c42"
        ),
        ciphertext: &hex!("57e6d821079bb8a79027f30e25"),
        tag: &hex!("de8c26d5a3da6be24b3f6ea1e2a0f0c6"),
    },
    TestVector {
        key: &hex!("eca22b3a29761fd40031b5c27d60adbcfac3a8e87feb9380c429cfbcda27bd06"),
        nonce: &hex!("4e6fe3d1f989d2efb8293168"),
        plaintext: &hex!("44d6a6af7d90be17aac02049a4"),
        aad: &hex!(
            "29beb1f0bb6b568268b9c7383991a09fd03da7e1639488169e4f58ec6451cad6d4c62086eee59df64e52a36527733d8c"
        ),
        ciphertext: &hex!("9aaa295bb3db7f6335a4c8cf2f"),
        tag: &hex!("55f7577163a130c0dbcde243ef216885"),
    },
    TestVector {
        key: &hex!("fa3ce8b099f3a392624bc433b5265235b65c0952cfc54817be2a8003d057903c"),
        nonce: &hex!("3168b4e50efe96b3d3aed600"),
        plaintext: &hex!("84ed3ccd428d3783ecea180b3b"),
        aad: &hex!(
            "d451fa64d73b7d7eee8f8143c40bab8e3f7a58ee018acda23224974f64ac7e1e389f5058ec08664bf56492b932d15f42"
        ),
        ciphertext: &hex!("ee2bd527568a4e7537c8f939b6"),
        tag: &hex!("f4615f7dfdffec8a2d52c992456210ad"),
    },
    TestVector {
        key: &hex!("ff9506b4d46ba54128876fadfcc673a4c927c618ea7d95cfcaa508cbc8f7fc66"),
        nonce: &hex!("3742ad2208a0484345eee1be"),
        plaintext: &hex!("7fd0d6cadc92cad27bb2d7d8c8"),
        aad: &hex!(
            "f1360a27fdc244be8739d85af6491c762a693aafe668c449515fdeeedb6a90aeee3891bbc8b69adc6a6426cb12fcdebc32c9f58c5259d128b91efa28620a3a9a0168b0ff5e76951cb41647ba4aa1f87fac0d97ac580e42cffc7e"
        ),
        ciphertext: &hex!("bdb8346b28eb4d7226493611a6"),
        tag: &hex!("7484d827b767647f44c7f94a39f8175c"),
    },
    TestVector {
        key: &hex!("b65b7e27d552395f5f444f031d5118fb4fb226deb0ac4e82784b901accd43c51"),
        nonce: &hex!("2493026855dd1c1da3af7b7e"),
        plaintext: &hex!("8adb36d2c2358e505b5d214ad0"),
        aad: &hex!(
            "b78e31b1793c2b758494e9c8ae7d3cee6e3697d40ffba04d3c6cbe25e12eeea365d5a2e7b46c4245771b7b2eb2062a640e6090d9f81caf63207865bb4f2c4cf6af81898560e3aeaa521dcd2c336e0ec57faffef58683a72710b9"
        ),
        ciphertext: &hex!("e9f19548d66ef3c16b711b89e2"),
        tag: &hex!("e7efc91bbf2026c3519010d65628e85f"),
    },
    TestVector {
        key: &hex!("8e4f8859bc838f6a2e7deb1849c27b78878285e00caad67507d5e79105669674"),
        nonce: &hex!("e71d0ebb691a4c31fdd9879c"),
        plaintext: &hex!("bd1713d8d276df4367bf3cbb81"),
        aad: &hex!(
            "47ca6cef3ca77997ef1b04e3721469be440ad6812aa3674ae92ca016b391d202e29932edfa83029eccae90bd8dbe4b434e7304b28fe249b380b2c3c49324fd5b3e469e3e135abc1c9fd77828b409c7482e6a63461c0597b14e5c"
        ),
        ciphertext: &hex!("eecbfb74e314628b0e3f827881"),
        tag: &hex!("c9ea890294d7e10f38b88e7c7493c5f8"),
    },
    TestVector {
        key: &hex!("2530cdcb2a789000822588a31bdc87c09234838da2d6ae1259c7049186525f11"),
        nonce: &hex!("0c509faa257dbb0e743a53ac"),
        plaintext: &hex!("a8edc524930ce4c20897c66f75"),
        aad: &hex!(
            "92a92cb8c1984ede806028cc45ac95574167ee83f03a707cc4b0fb8ad70907e0016e38b650f4a75bc83a625e3c670701d43bfb0326d1c4fe7c68410733c0c874c920389d164bf67a9032e2e837f5e9e324b97932d1f917ba7dca"
        ),
        ciphertext: &hex!("1f658c7a1f41152b22999ed1b7"),
        tag: &hex!("cf3e4fef775d9c6ff3695be2602a90d8"),
    },
    TestVector {
        key: &hex!("54c31fb2fb4aab6a82ce188e6afa71a3354811099d1203fe1f991746f7342f90"),
        nonce: &hex!("f0fe974bdbe1694dc3b06cc6"),
        plaintext: &hex!("fbb7b3730f0cd7b1052a5298ee"),
        aad: &hex!(
            "2879e05e0f8dd4402425eabb0dc184dcd07d46d54d775d7c2b76b0f76b3eed5f7ca93c6ae71bf509c270490269ea869ed6603fdf7113aa625648ab8ed88210f8b30ec9c94bca5757ca3d77491f64109101165636b068e3095cb4"
        ),
        ciphertext: &hex!("3a5a2a8aa93c462cfb80f1f728"),
        tag: &hex!("59ef9d54ee01fb6cd54bd0e08f74096f"),
    },
    TestVector {
        key: &hex!("8084061d0f7858a65c3a3557215ed46f1590278ca97a45dcb095d2a0979f2e3f"),
        nonce: &hex!("6973898b1a8f72856415675b"),
        plaintext: &hex!("200d0445cb09eb52f54d2f74c6"),
        aad: &hex!(
            "8b543e294546848c3308ccea302f0238b7dffc1706d03657c190ea745cc75bcd5a437993e787828ea7fe42fea1d5c6f7229a72ea65f0d0c190989a590ab49c54726633282c689eef8cf852af263b5edf63e449fd5440730003ca"
        ),
        ciphertext: &hex!("ec242c358193ca6187c89aa7a5"),
        tag: &hex!("967428ac6956525ba81d5901ed259407"),
    },
    TestVector {
        key: &hex!("2aad7db82df4a0d2ec85218da9d61ade98f65feeb8532d8eb728ef8aac220da6"),
        nonce: &hex!("029ac2e9f5dc3d76b0d1f9df"),
        plaintext: &hex!("ba363912f6207c54aecd26b627"),
        aad: &hex!(
            "d6f4b6232d17b1bc307912a15f39ccd185a465ee860279e98eb9551498d7b078271ebabdda7211e6b4ab187043171bc5e4bf9ffcf89a778430e735df29410a45ca354b0003433c6bc8593ee82e7c096a32eac76d11daa7d64150"
        ),
        ciphertext: &hex!("bfcad32611da275a0f0821517c"),
        tag: &hex!("9ea37bdcaafad69caf06d67fb18dd001"),
    },
    TestVector {
        key: &hex!("f70bb950ab56f12f1efc2376d32a59d16ef3ef5969e0106ab40cc314c9b0c7e8"),
        nonce: &hex!("3b3b29ba422c2bacafeeb8b3"),
        plaintext: &hex!("029929277043dc0379f152a484"),
        aad: &hex!(
            "464ac0c84b9ff17a0e7c39a65f89682a89b8787553a6275f0d55effaabef2114072c739f9831a5d5a5133ae4de14eb51346b318b255a1bff57e50c433e1e69a00fe1a8b6f6b621d515d670d89e148f6b65d6eb4c54878cb819ce"
        ),
        ciphertext: &hex!("c0b97d6d1a95d708d6dc7d2b95"),
        tag: &hex!("322eb4395bf4d4dd070b8f9f6195f8ee"),
    },
    TestVector {
        key: &hex!("f4950f01cb11fdd9afb297f7aa852facfac354ff96557befa5f657678de6cefb"),
        nonce: &hex!("aba7d864f29cbc449cd93e33"),
        plaintext: &hex!("e6daf59ef54ac7405984fc4c4e"),
        aad: &hex!(
            "852f624cea7a8c20e189e0c79f578c0d770c4bf7c4e691649eba992f6de89d7bf2078aff94803a3dc62628e02a80a01957722e2a931fc56283d84ab68ce11ae867835c2d9700df130048ea8eaaca41f1a9059be2acaea6e0f7f2"
        ),
        ciphertext: &hex!("d01d36ff8009b4082279abb906"),
        tag: &hex!("d9a36c8008493bd95c09049299cbd075"),
    },
    TestVector {
        key: &hex!("714261ef4f02fb4efb0e6b5aed96d7b3ceac6551a57cf679da179c01aac5ee0e"),
        nonce: &hex!("3b7d15c7fd877461a789255a"),
        plaintext: &hex!("815de8b0382fe60cb0d3782ee9"),
        aad: &hex!(
            "7621e58152336ee415f037f2e11581fe4da545c18d6e80177d5ab5dda89a25e8057d6fccec3757759a6e86e631080c0b17baa8be0b8fe579d3bfa97937ee242b6faacfc09425853df4dc26bc263ed1083a73ffc978c9265f8069"
        ),
        ciphertext: &hex!("29c566ea47752a31a380fd0e7c"),
        tag: &hex!("b279340a384dbbae721c54e9183b3966"),
    },
    TestVector {
        key: &hex!("53459ba5a2e49d1a7c2fb6ad9e6961b4dbe5158cb9266eff425d6dcccaaf8073"),
        nonce: &hex!("3c97dc635a75fbe2c33c9a41"),
        plaintext: &hex!("03fbfe5842ed781990ca8be728"),
        aad: &hex!(
            "7fe308afe58a927680bee3368301f4dc7c47811fc09f1b9922a092a497b9c6b67c857fdcc32da1011acb110b3c1475bef303f1a609479485cc400ee8f38381c45d078708ad49f226f95dd9c81478d1ee2b53c3b906d96f8ddd76"
        ),
        ciphertext: &hex!("5865e5a1ec711732a4ee871bff"),
        tag: &hex!("856a653ec214178096bed423e30a36e9"),
    },
    TestVector {
        key: &hex!("f0501583c226d2519ed23fcc6f2cffd2f013eb91aa07b3a5a2073d6e2bd10cef"),
        nonce: &hex!("29a922ad9bdeddc2e298b99f"),
        plaintext: &hex!("035eb6922345c02a81435d9e77"),
        aad: &hex!(
            "d84f54bac09ea92afe0a7335cb0bb5f68425490fd2fb6c3b99218f49856ed427ec902e510b899d54951fe84cdbfd112608d1e999f64ecc9cd4be3a0114c1c34875dbf35a1b0be421659f99d69b32e968cebfca6f95837e3edeb4"
        ),
        ciphertext: &hex!("095971f99af467805a62bfb882"),
        tag: &hex!("d5ff2b7beac260e517ea3eca13ff1e77"),
    },
    TestVector {
        key: &hex!("78e6789b596c71cb3becc833cf823d2ebb18ca2e26c27e26a55ef95df7353971"),
        nonce: &hex!("65da9c7a9f17b11246bcf8db"),
        plaintext: &hex!("003e82a147df3c953400f87ab5"),
        aad: &hex!(
            "d49aee7ffd31e7c8d831d97ae894a00473adbc5071f6099d567caaef85c295d5143a1316ff82753cc35d3efc60f7e5101ddd811336b404d598f6c439cce6b47fcbebb15d1c342e4151b355025a03b4397260b4a7e6444fa57b5b"
        ),
        ciphertext: &hex!("abcceced40209fc30a5590fee8"),
        tag: &hex!("0a203973b81375949ebd932597efd495"),
    },
    TestVector {
        key: &hex!("816b3e6ca31d59688c20bcd1fa4285197735d8734289ca19a4730e56f1631ccf"),
        nonce: &hex!("4c191ac994f86985c180ccd4"),
        plaintext: &hex!("b2060dd86bc307133b7d365830"),
        aad: &hex!(
            "b3dcd643c68ccce186570c63288c8722b8a13dfaf9e71f44f1eeb454a44dddf5f955540cd46c9f3b6f820588f71936d7a8c54c7b7bc43f58bb48e6416149feae7a3f8d8198a970811627489266a871e8cb87878cdb3a48be65f5"
        ),
        ciphertext: &hex!("53e65880ad0012a75f1188996f"),
        tag: &hex!("9ca8a71a45eb4402a6b03106bae330d1"),
    },
    TestVector {
        key: &hex!("a07ba57478061bd7abddd762971cf2e47141891f76c3d1c150b53eee5704557d"),
        nonce: &hex!("5adfb85b2d9e239c5146501d"),
        plaintext: &hex!("67c8824c1837cfdec6edcd719c"),
        aad: &hex!(
            "937b3ed73e67ca0b02f9eb736a668362d4d0447c15f6083099a7f90c7c49318dd72f6baa74da22ff53b56c24fb9a1b1d6c4e29f4ac4d917220ebe3c8d760999da7be9e1e8f6a171133640c9196f9ee3cdb76a5a342a95a05c8c4"
        ),
        ciphertext: &hex!("1eb85c6682850e849eb37927e5"),
        tag: &hex!("8079f705cf551a5484132cd0f0c5297c"),
    },
    TestVector {
        key: &hex!("268ed1b5d7c9c7304f9cae5fc437b4cd3aebe2ec65f0d85c3918d3d3b5bba89b"),
        nonce: &hex!("9ed9d8180564e0e945f5e5d4"),
        plaintext: &hex!("fe29a40d8ebf57262bdb87191d01843f4ca4b2de97d88273154a0b7d9e2fdb80"),
        aad: b"",
        ciphertext: &hex!("791a4a026f16f3a5ea06274bf02baab469860abde5e645f3dd473a5acddeecfc"),
        tag: &hex!("05b2b74db0662550435ef1900e136b15"),
    },
    TestVector {
        key: &hex!("c772a8d5e9f3384f16be2c34bf9afd9ebf86b69e6f610cd195a9db169e9be17e"),
        nonce: &hex!("9b8e079f9971d7352e6810a3"),
        plaintext: &hex!("7f13fcaf0db79d792823a9271b1213a98d116eff7e8e3c86ddeb6a0a03f13afa"),
        aad: b"",
        ciphertext: &hex!("d29e2bf3518668a14f17a3e4e76e1b43685734b801118d33a23238f34d18aa40"),
        tag: &hex!("8e02b0b7d172cf5e2578f5b30fac2e7a"),
    },
    TestVector {
        key: &hex!("d5924b31676e2354fe7dafffaf529749598ea1bf5e4c44f5b60240e09d8036aa"),
        nonce: &hex!("5d847784f0bcd79cb84fcf1d"),
        plaintext: &hex!("6fd80c8f0d4de081a93c16b84dec697a1e4f9d80a6af497c561572645eac0d63"),
        aad: b"",
        ciphertext: &hex!("282cc9d2308a443019cfdc4d79854accc7731ee36902bafe3ffaca6484327b82"),
        tag: &hex!("4dc5e0f2ab91bdfd31f2bdcf06af9667"),
    },
    TestVector {
        key: &hex!("b328c6d7946221a08c4f0509b52992a139890cdd8eae1956851f110c49602cb5"),
        nonce: &hex!("1a433c33ca12ce26cf3dffff"),
        plaintext: &hex!("217bdc314a4d335c72b5267b424fc8e31f4bb118e6cfaeacf5548f4ba8f51980"),
        aad: b"",
        ciphertext: &hex!("a322944e07bf84ab424ffa75fd0309e8691c9036b08f344ba76ce0774f43b351"),
        tag: &hex!("14dd6b1c2b224533ccc9fee8d2881358"),
    },
    TestVector {
        key: &hex!("c2080965d21d229c0d0d6c56cbce83880120c21a48172a64560b90dc4ce1ffbe"),
        nonce: &hex!("928d6c0195f5f0974f38730b"),
        plaintext: &hex!("864397271e1b242aa1dff38e78aa89353e1554ba907318a0aaad44f26fcd567d"),
        aad: b"",
        ciphertext: &hex!("7de4f941f44bd0f268b2a47b9c4927cc10537bbed739d52ab099fde4033041d1"),
        tag: &hex!("b51a59931817257619e7be1091128c49"),
    },
    TestVector {
        key: &hex!("dd6b7e2584edf1f1e6c2c0dd1f72161a92d2cba99856554f820de1256d48c099"),
        nonce: &hex!("fe9d553c75067e8dbae1ab67"),
        plaintext: &hex!("f9f86f7762859f11d6e7ef56178657ddcded532843446f86a23eac35aa2dd3c0"),
        aad: b"",
        ciphertext: &hex!("f7aaa1711c8092783b05b4e5e6c9c6944e991bd59c94b9d0356df00a66e2db5b"),
        tag: &hex!("c61edd176c8322a01d8c5f3df09252e9"),
    },
    TestVector {
        key: &hex!("37f39137416bafde6f75022a7a527cc593b6000a83ff51ec04871a0ff5360e4e"),
        nonce: &hex!("a291484c3de8bec6b47f525f"),
        plaintext: &hex!("fafd94cede8b5a0730394bec68a8e77dba288d6ccaa8e1563a81d6e7ccc7fc97"),
        aad: b"",
        ciphertext: &hex!("44dc868006b21d49284016565ffb3979cc4271d967628bf7cdaf86db888e92e5"),
        tag: &hex!("01a2b578aa2f41ec6379a44a31cc019c"),
    },
    TestVector {
        key: &hex!("a2ef619054164073c06a191b6431c4c0bc2690508dcb6e88a8396a1391291483"),
        nonce: &hex!("16c6d20224b556a8ad7e6007"),
        plaintext: &hex!("949a9f85966f4a317cf592e70c5fb59c4cacbd08140c8169ba10b2e8791ae57b"),
        aad: b"",
        ciphertext: &hex!("b5054a392e5f0672e7922ac243b93b432e8c58274ff4a6d3aa8cb654e494e2f2"),
        tag: &hex!("cf2bbdb740369c140e93e251e6f5c875"),
    },
    TestVector {
        key: &hex!("76f386bc8b93831903901b5eda1f7795af8adcecffa8aef004b754a353c62d8e"),
        nonce: &hex!("96618b357c41f41a2c48343b"),
        plaintext: &hex!("36108edad5de3bfb0258df7709fbbb1a157c36321f8de72eb8320e9aa1794933"),
        aad: b"",
        ciphertext: &hex!("b2093a4fc8ff0daefc1c786b6b04324a80d77941a88e0a7a6ef0a62beb8ed283"),
        tag: &hex!("e55ea0456af9cdff2cad4eebbf00da1b"),
    },
    TestVector {
        key: &hex!("6fb2d130bbad1924cab37d071553b12169e978a805bf74cb4c23d5ccd393d7bb"),
        nonce: &hex!("76826741225a391fdce4d3b6"),
        plaintext: &hex!("c49b80080e2efeb5724b9e5b53ba0c302e97bd16f1a6bbec01e1ca6c35a42a3c"),
        aad: b"",
        ciphertext: &hex!("62fbe5466a7ff83ff719f4927e00e9319e1bb7e835c5d6b4e9d4bc5a8d6e2beb"),
        tag: &hex!("df72da7a66cb5257836f3c19ecadcd55"),
    },
    TestVector {
        key: &hex!("402e8113970257d9437807620098370243536a105cca4fbc81a1ff2d48874f48"),
        nonce: &hex!("c924c19c4d14905a2bdf63bf"),
        plaintext: &hex!("917b9585f65e59bf4d242bb0802966045dd29fbc66911277baecdfcc818c3c35"),
        aad: b"",
        ciphertext: &hex!("5b6594edcddbb338f4e813687f4f23a75a64c21e3cf5d2e7c9af0f7e3ee3e616"),
        tag: &hex!("f1cccd93a4411247c8b6830addd72c6f"),
    },
    TestVector {
        key: &hex!("2aac499cb0eb72b4598acff4330df6cd764978997d5ace51da88e0c18671bde9"),
        nonce: &hex!("fd16cdc39d7f0b92e1f95c97"),
        plaintext: &hex!("e7b75bfa35c9a004d0b68265623a9b06b6d4493ea0ad4f6c777ba5add8c7bbbb"),
        aad: b"",
        ciphertext: &hex!("c3d0a0f7ce9720c95aac86151aad634884ddfa62df58f18394537f6504d9a8aa"),
        tag: &hex!("76749a1ec70236b267fc340d5fbb6da3"),
    },
    TestVector {
        key: &hex!("a2a502d6bb19089351e228d5cbff203e54fc31f2772253df08557875d964c231"),
        nonce: &hex!("0ebb5af4a462a1e6ded7164a"),
        plaintext: &hex!("bbecc89450c07b8de631155e5d7cc7a9d26376bb57d7458d49b4c36e140490f3"),
        aad: b"",
        ciphertext: &hex!("fd09c950890441fcaaa8809a8998079abb88741c6672abae12383ffd724f8299"),
        tag: &hex!("22fac246058bf142c5f26812a635b480"),
    },
    TestVector {
        key: &hex!("ce2d289e20c76f75c135c8118d5cbf5f2828026f0b639588a3eb4ad752cea548"),
        nonce: &hex!("bb08526dd8bd1c3bb58d0999"),
        plaintext: &hex!("56f5db1e796a0c4633a8d570182c39e3c8451e7ba485b98d38a2c926a1b92a46"),
        aad: b"",
        ciphertext: &hex!("a41005df18734d4f3f99f19ef8fc43b16ef431207cb0466341bf164b58e23533"),
        tag: &hex!("a45c2a1ef6aec75cc22d71807dab3c27"),
    },
    TestVector {
        key: &hex!("66e418d0ec97b420b1b5365d1b6d5cd7c5ac1a5653739120d4aec3c94c93c287"),
        nonce: &hex!("989f94480266e3652488184e"),
        plaintext: &hex!("e5052b19d7f827fd60f45c8925809fd2217ec4d16aa89bbf95c86a1c1e42bd36"),
        aad: b"",
        ciphertext: &hex!("f341630574ee92942cf4c5ecd3721ae74b32c557379dfe8351bd1c6661a240da"),
        tag: &hex!("e85fb655ef432e19580e0426dd405a3e"),
    },
    TestVector {
        key: &hex!("37ccdba1d929d6436c16bba5b5ff34deec88ed7df3d15d0f4ddf80c0c731ee1f"),
        nonce: &hex!("5c1b21c8998ed6299006d3f9"),
        plaintext: &hex!("ad4260e3cdc76bcc10c7b2c06b80b3be948258e5ef20c508a81f51e96a518388"),
        aad: &hex!("22ed235946235a85a45bc5fad7140bfa"),
        ciphertext: &hex!("3b335f8b08d33ccdcad228a74700f1007542a4d1e7fc1ebe3f447fe71af29816"),
        tag: &hex!("1fbf49cc46f458bf6e88f6370975e6d4"),
    },
    TestVector {
        key: &hex!("2c11470e6f136bec73351619288f819fb2bbba451857aadfb78384074612778a"),
        nonce: &hex!("4e6cc2bcc15a46d51e88958d"),
        plaintext: &hex!("3b3186a02475f536d80d8bd326ecc8b33dd04f66f8ba1d20917952410b05c2ed"),
        aad: &hex!("05d29369922fdac1a7b37f07953fe175"),
        ciphertext: &hex!("6380945a08977e87b294b9e412a26aebeeb8960c512439bac36636763cd91c0c"),
        tag: &hex!("1029a3c4be1d90123c1b404513efde53"),
    },
    TestVector {
        key: &hex!("df25ea377c784d743846555a10cfaa044936535649e94da21811bad9cea957b5"),
        nonce: &hex!("35f5f8e950c1f57ad3dfb1fa"),
        plaintext: &hex!("98941a807ac8f16eef0b3d3c7bbdfd55d01736c5b3360d92b4358a5a8919380b"),
        aad: &hex!("28eb4677110ccb6edc8d2013dc8f46ec"),
        ciphertext: &hex!("24a07532e981aaf3106eab8dfbb2d2078342e2eaee027e148f06aca68f6a1c50"),
        tag: &hex!("131373ed4a0e3f584ae978d42daa6f3a"),
    },
    TestVector {
        key: &hex!("106168ea651f22c54196a06f1a10bcf4e620d93e4dc0824d798f44f9219c6177"),
        nonce: &hex!("4064dcbd631cf20b05ae22de"),
        plaintext: &hex!("b0d3da2b96b8889c92e445abbea4c6d0d5d44d7fbcc7dade4c92f6bcddbf06e1"),
        aad: &hex!("a36e2fb9cd96a8ca9ae2b193aa498efd"),
        ciphertext: &hex!("f55a6d8a6965ea451637bec7548cfb1ffe59fc0ce6ea6a937cb5dd32b3d45d5f"),
        tag: &hex!("8d1bf2715041f817f11631fc9910c629"),
    },
    TestVector {
        key: &hex!("272d1649a3dd804de0962d3e07064a7054c00a6234ab1b0cdcf685ab394837e5"),
        nonce: &hex!("955b5897f6b9806bbec5c33e"),
        plaintext: &hex!("36e57c29c08c51ad7fa91c0416f976cfd011780eb44cc5abd34c7b431b093b8d"),
        aad: &hex!("33e618ecbbe5eb0566df21c3c34b7e25"),
        ciphertext: &hex!("cd6aeb345081dc0bb2c8b4d19b280658fb87c0f2bd0f4c9da694dc1feeb32f4e"),
        tag: &hex!("dd37eac6bd6a4d3618241738779735d7"),
    },
    TestVector {
        key: &hex!("3dab6a51bb7af334dd4b79a7d139550c88f0778d43c21fc4ad33f983a13515cb"),
        nonce: &hex!("362eaa67cab3d1ed48e9f388"),
        plaintext: &hex!("3eb7f5f0a4ca9aa7000497602c6124433a60a8fcd91b20175b4ee87e6b10a2d7"),
        aad: &hex!("52852150786e6547a2618e15c77110b6"),
        ciphertext: &hex!("cc3316041b88733839249b756ffa00bbec6211942f604f26c4a35ed32e6eeaff"),
        tag: &hex!("5936c5500240d50c0da0fcdc248f176e"),
    },
    TestVector {
        key: &hex!("0ea606521b935d5b4b66df89fb372d35c4d6d2c03767367e38de0d4c27761d56"),
        nonce: &hex!("0d3168318a4f76392699640b"),
        plaintext: &hex!("f450b36d6c49411897bce39001d73ff01b5e8566179e36dacac7064cab5c6270"),
        aad: &hex!("3bd8849070cf034c4298f40f33b0b839"),
        ciphertext: &hex!("3b15fad18726c4eaa70502b3f3b32c5092d1d92835e6460665fc50dda953a191"),
        tag: &hex!("11fd3fddf61e010c17fbedd4bd5fb012"),
    },
    TestVector {
        key: &hex!("c8c4f9e0bd289ef1bd16104a8074fb073dd9035ab937ab076fb5801e2295aa2f"),
        nonce: &hex!("be699d9d98ec1f724da8bd0f"),
        plaintext: &hex!("49fe9407a719d41e658587809cfed7a5b49941c2d6378f3c0afe612f54f058a1"),
        aad: &hex!("a985c7489732038c3190cb52be23737c"),
        ciphertext: &hex!("17a9aaa6a3c68ba1f6cb26fdd6536c207e3c9ce58f43e4ecfd38d3387a798a0f"),
        tag: &hex!("d832cb4814142562fedfe45b36126cb8"),
    },
    TestVector {
        key: &hex!("52d0f20b0ca7a6f9e5c5b8549d5910f1b5b344fc6852392f983558e3c593be24"),
        nonce: &hex!("d5c618a940a5a5d9cc813f27"),
        plaintext: &hex!("a9fed8a29355685321f978e59c40135309306cd41b25349fe671dc7990951c68"),
        aad: &hex!("61823f7e39ed76143ca7249d149bdf57"),
        ciphertext: &hex!("509c540e558d0bf0a3b776cddfbfddc15486748a7f9952b17c1cbd6869c263f4"),
        tag: &hex!("42e35ee3f7119f87fb52b5d75b8ab8ec"),
    },
    TestVector {
        key: &hex!("5d291a8f1a6433a41076702d9d8a8c196e464550ed900ce8c2a36f4d10483954"),
        nonce: &hex!("c4ba743ee692e5d00b5ae2c6"),
        plaintext: &hex!("605d519b26182458fea68dddd86033390fc545f843ae817850a2a4574add015d"),
        aad: &hex!("878fa6720ab30e0287f6903acd2dca19"),
        ciphertext: &hex!("1c2f153f2374d3945cca9757dc18d9a15a93276526285a6e316ee32a72092c34"),
        tag: &hex!("e7905e856c88c6ece4bb47781becf923"),
    },
    TestVector {
        key: &hex!("09e2724d4017cd57e967000e4da2cd5c5c18ccfb06c33b7ce62a7641e4bb0b73"),
        nonce: &hex!("9ea18b420a10177289ab370b"),
        plaintext: &hex!("6f5dfa86d5df4febd752265c56390049e7cda60c2644c84ab413932faad15b15"),
        aad: &hex!("a8e77939423d5894d307fd60278d162a"),
        ciphertext: &hex!("35e37a9b913eb58b72262e92d7584d44bf9a8442f1b2f3da3a5d05ec6a2a31e2"),
        tag: &hex!("1a95023b1a4a3e885520ec79e1a3aef9"),
    },
    TestVector {
        key: &hex!("8544a9f4f6c0efdff3da90cfa3ee53fbe1f8de159d29537c803e1651da153718"),
        nonce: &hex!("be406029a1d0c25d09af94cf"),
        plaintext: &hex!("7e88a65646ed138b7c749366d16e41dbafd9987ad2373bb9d0b6ce0c1a4d6661"),
        aad: &hex!("599dbb73897d045a1bd87385e60323a2"),
        ciphertext: &hex!("38ffbf9ffff8d6a92090584e6dace1c6a47d3d5709a25e470557d5c8f5dd1851"),
        tag: &hex!("d5b2e83c47df404de9a7cd95d3cbe7ab"),
    },
    TestVector {
        key: &hex!("35b9d2a5db3b06e7720cec794dae615029a491c417f235498e0496cd8183d1bf"),
        nonce: &hex!("b382987916e19752dd9ecc0c"),
        plaintext: &hex!("76b290496901c5824ad167433dbb6d6b5856d41913ee97ec81e70cf6a170e35c"),
        aad: &hex!("e0aa3a1f1df601366c59a390f4f06c3b"),
        ciphertext: &hex!("78347400d6799e77e11e76c0ecfd311becf31f74f14b3a71e6d526ce57015c8b"),
        tag: &hex!("bf8dec2feac7cfe9f330bdfc92737b33"),
    },
    TestVector {
        key: &hex!("d707eab3c167b73efeb08c50e12b1569a275487ea136f52736c0f3ce66b69fa3"),
        nonce: &hex!("11116f34182e52428642e747"),
        plaintext: &hex!("a0c4818362035b16b50de445d558ea5cf8844bf5c84b96232999a2279806cc45"),
        aad: &hex!("ae9f90331800c358716c92667f79f748"),
        ciphertext: &hex!("91c77404b20028ef0fd4dd7f8b65b6594af94a1e7fc79cfbdb108265354fc71b"),
        tag: &hex!("6c3410d4b915dbad745715202c04e9a4"),
    },
    TestVector {
        key: &hex!("405d13ee48d3b9fc26bcfca776b2af6c745d8fc34171622f8c6c4be5a54b8b65"),
        nonce: &hex!("add1524abb1b846f0f6577da"),
        plaintext: &hex!("e06475990d6e3990266de1bd025c3b1910c0736c81050885f2bfc13ec78e9d96"),
        aad: &hex!("0b1c4c3ba877bca5846b2c1f2b0e2105"),
        ciphertext: &hex!("6399f7e6d6c680fc41bac8bee3836b9a4241403d5a19e4919f396ce37b238d38"),
        tag: &hex!("e754f400d76c76e03c63ea88cf64ccba"),
    },
    TestVector {
        key: &hex!("5853c020946b35f2c58ec427152b840420c40029636adcbb027471378cfdde0f"),
        nonce: &hex!("eec313dd07cc1b3e6b068a47"),
        plaintext: &hex!("ce7458e56aef9061cb0c42ec2315565e6168f5a6249ffd31610b6d17ab64935e"),
        aad: &hex!("1389b522c24a774181700553f0246bbabdd38d6f"),
        ciphertext: &hex!("eadc3b8766a77ded1a58cb727eca2a9790496c298654cda78febf0da16b6903b"),
        tag: &hex!("3d49a5b32fde7eafcce90079217ffb57"),
    },
    TestVector {
        key: &hex!("5019ac0617fea10517a2a2714e6cd369c681be340c2a24611306edcd9d5c3928"),
        nonce: &hex!("fd1fa6b5cab9aa8d56418abb"),
        plaintext: &hex!("4349221f6647a906a47e64b5a7a1deb2f7caf5c3fef16f0b968d625bca363dca"),
        aad: &hex!("953bcbd731a139c5de3a2b75e9ffa4f48018266a"),
        ciphertext: &hex!("dbce650508dab5f499767651ee734692f7b157341977692d2ca879799e8f54aa"),
        tag: &hex!("20239e97e2db4985f07e271ba545bbbf"),
    },
    TestVector {
        key: &hex!("c8cee90a8b9ad6094d469e5d1edc30d667608e89b26200cac77efd7e52af36fd"),
        nonce: &hex!("5a1aa9c8e635281ee1fb9df7"),
        plaintext: &hex!("728d9221891bd75c8e60b7dd6f53edcfd1ab1cebc63a6ce54be220b5b362233b"),
        aad: &hex!("0538b3b64da72aac591bc59991a140eff206b3f7"),
        ciphertext: &hex!("b753eb6b87f0c8778c3ea3a74fba3b31ced6d2da94d43d482ab0431806a80d75"),
        tag: &hex!("b21d29cf6fd04571ffcaf317d384df11"),
    },
    TestVector {
        key: &hex!("b4b77710f86ffd463fc14bb9eaa4424b2b3a581778e5511a094a08fb204cab59"),
        nonce: &hex!("3e4b12bf55633bf48d104620"),
        plaintext: &hex!("6f44a8df11dce27df075ea10ddeb7566ca6c988a334cf56e8540f71166d7c0d1"),
        aad: &hex!("3e3b4c9369266266098326217b5677a40297cb87"),
        ciphertext: &hex!("31f82f5cb1cd5c4b4819b61aa9377abebe8fca76978b1199178462c7c1c4e2b2"),
        tag: &hex!("1b3a535768e8480d75ec91b2e7b55efd"),
    },
    TestVector {
        key: &hex!("0a8fb75498a139223c763d52bbe3d42f813de370fa36b81edc4553d4219d2d5d"),
        nonce: &hex!("7d6cb675fded3efef908a11a"),
        plaintext: &hex!("81b69ca354de3b04d76ee62334cb981e55f0210f1174d391655d0f6712921a0e"),
        aad: &hex!("2314ad86b248f1ed2878e7c562b533bf2dda5a29"),
        ciphertext: &hex!("6a23d30737f4a72b1e07ba23d17fde43a4498e2e60d3e1b0c8e6ea26a2bb331a"),
        tag: &hex!("7fcac442fb657910c62a74b1d0638902"),
    },
    TestVector {
        key: &hex!("a84315058849690c2b88062aef81134d338526baa7090e865fcaad94bbf51ca5"),
        nonce: &hex!("a487cfa701447b495aab41e0"),
        plaintext: &hex!("18074e14dc0a14d4439f1d710927ed8c200154c8492f77f10f653e0bf6070ca6"),
        aad: &hex!("7c4416b0cf13ac76bec6687a6840dc703e91bb86"),
        ciphertext: &hex!("80f40b7e335d40fc5859e87f385e14798a253818e8ad73b1799c1419638246a4"),
        tag: &hex!("b4c7c76d8863e784eb6029cd160ef6de"),
    },
    TestVector {
        key: &hex!("82833bcaaec56f6abbb3378f7d65daf6e6f6f2a0d1e858c7219f53a7840f4e00"),
        nonce: &hex!("4bc9b028a00be8feb5232978"),
        plaintext: &hex!("d9b2383123a27a93bce85add8392b938093b40e82f182e484bf4f84fa3bfb3f0"),
        aad: &hex!("76fc8ed57154cd8a9b3d02c87061edd2a8157811"),
        ciphertext: &hex!("383efe971438cd2b2cbb399d74a3fb3eedd394f1862addc58e9fdd4c421402d2"),
        tag: &hex!("fd803c4fa917f7ff649a6aac013a96b1"),
    },
    TestVector {
        key: &hex!("ee4634c49c5672c660968a42862698f6c1b2c7b79efd1605c24af8ff9ff8366c"),
        nonce: &hex!("877912b2f35888d2810612cc"),
        plaintext: &hex!("9512a5268a0cb3fbd916ddb820dce77f1e0dbb52c8ffc7a74be077119e9245e4"),
        aad: &hex!("93bd669db4f1354ef6c8addb0cf729e46d5c3846"),
        ciphertext: &hex!("69af0ac954e0d69043851d89f1538ebcb42769857eba27dbe4ad4fd60fd75537"),
        tag: &hex!("3ee443873e2f7f7ea601fe3d7e5211e2"),
    },
    TestVector {
        key: &hex!("442f4bbc468433411e49486a15c5eed577f5007380ff126d9974f3bd3fe4e3c4"),
        nonce: &hex!("1e7133aaa8af826dc646ec62"),
        plaintext: &hex!("7f8069e5c356ece135d98bb563c8b411ea90ea3b673dfd92e1ba9c459efae61f"),
        aad: &hex!("577662f611446b5b31814930029edb949a30dcb9"),
        ciphertext: &hex!("b962952750eb2bce313e1a85a72e3c9cc2ea7e58c353ea37df2c9f0723995ca7"),
        tag: &hex!("e633fe9f10cedf0f0d02aa2ddcf47d86"),
    },
    TestVector {
        key: &hex!("3a29aec009f44fdd2b1bc07cb7836f29d8589774bd0d74089a68d9e67827d6d8"),
        nonce: &hex!("a42c5fb61573c72688ac31d8"),
        plaintext: &hex!("d36eb81506c0a0e4ebcac9b4b1acebb38b94b8f2ce3d6f85a8f705fa40cb987a"),
        aad: &hex!("2ee2582d544e1663f1d7a0b5033bcb0fce13b3e5"),
        ciphertext: &hex!("179ef449daaacb961f88c39b4457d6638f304762bd695924ca9ebd01a3e99b9f"),
        tag: &hex!("1fee176c7a5d214748e1d47b77f4bcc8"),
    },
    TestVector {
        key: &hex!("ed47660054294f3c913c97b869317cbddc395d757bef7d29b8ccbdd2c54e99d3"),
        nonce: &hex!("770a00642c67eff93c9f1f56"),
        plaintext: &hex!("034193397cbd0eb414459273a88808db2d0711e46f80d7883212c443d9e31b54"),
        aad: &hex!("06210fca2018d2357256c09197730e9777caea96"),
        ciphertext: &hex!("6a250ebd3390229d46b691142743dba1c432c0feaa0f0dd19d0ce4e6a8918d80"),
        tag: &hex!("a5f6e975592b472907c34b93bfc69dde"),
    },
    TestVector {
        key: &hex!("9539844493362dc3f913308f7e12a2a0e02afdbd8869877b30ce0397fb0349dc"),
        nonce: &hex!("eadda3132079195a54fde2c1"),
        plaintext: &hex!("62349a0b1e40a9f31eadf27073682da15f0a05cf4566ee718b28325f7d8eaba0"),
        aad: &hex!("0ae4a90cb292c4e519b525755af6c720b3145a1e"),
        ciphertext: &hex!("ad6c9521bf78d1d95673edd150f2b8dd28f10625d67fa25f1fb42d132ba7fcfa"),
        tag: &hex!("916242a9cb80dffcb6d3ae05c278819a"),
    },
    TestVector {
        key: &hex!("3b4eb08d27ae0b77605ae628a1b54a5402026550679fab0a20752bee510d3d92"),
        nonce: &hex!("28a20c40f49a00493da3488a"),
        plaintext: &hex!("c8a47edcf84872f53f96ef41ce05ca37cbc3854b556d6e606f0a8a32d0861907"),
        aad: &hex!("0591390e2d14ebe62aeb1741c26448ce55b28cab"),
        ciphertext: &hex!("a3e8cbf84df8529838f79315c7f1a0b7bb3ad4c4d036ec317b1810b274ee3080"),
        tag: &hex!("0a8f66daeb7f0a88756909c4e93fcd36"),
    },
    TestVector {
        key: &hex!("0cccea8f1f6ce141690e246cf4cb9f35b66baf6e6986b8e0b4cfdd13fcdbc8c3"),
        nonce: &hex!("929f07be5aa7bae7607bae3c"),
        plaintext: &hex!("9fa5214c599523c695d37937b02f78837f6406960b2a03bf9a6db34bd35e3dc7"),
        aad: &hex!("b851e610be70a994808b34ca73f45f1ea973de65"),
        ciphertext: &hex!("917ecc8b00b53f7fb0732d66848a106e91f60acf2dcf180832a74d5993c658da"),
        tag: &hex!("2959e20746bbb6ab66dfd29b9477799a"),
    },
    TestVector {
        key: &hex!("ecbfaef2345b34f31fbf6d68efb385e5833df8b6e6ae621ede02baf9735d2dba"),
        nonce: &hex!("50c3527b1a35ccb318b446de"),
        plaintext: &hex!("634f6dd60783d1f952353fd1d359b9ee4f4afa53cc13e81c5adfe24b46baf08f"),
        aad: &hex!("f8981548bde6ee6c1745f947de191bf29997fadf"),
        ciphertext: &hex!("705e5f67ab889ba238118e3fd9b90b68be801995ae307378d93b50977cf90588"),
        tag: &hex!("12d14468ac18cc9936bd565f8ad42d0d"),
    },
    TestVector {
        key: &hex!("dc776f0156c15d032623854b625c61868e5db84b7b6f9fbd3672f12f0025e0f6"),
        nonce: &hex!("67130951c4a57f6ae7f13241"),
        plaintext: &hex!("9378a727a5119595ad631b12a5a6bc8a91756ef09c8d6eaa2b718fe86876da20"),
        aad: &hex!(
            "fd0920faeb7b212932280a009bac969145e5c316cf3922622c3705c3457c4e9f124b2076994323fbcfb523f8ed16d241"
        ),
        ciphertext: &hex!("6d958c20870d401a3c1f7a0ac092c97774d451c09f7aae992a8841ff0ab9d60d"),
        tag: &hex!("b876831b4ecd7242963b040aa45c4114"),
    },
    TestVector {
        key: &hex!("07b3b8735d67a05632c557076ac41293f52540bac0521573e8c0414ec36f7220"),
        nonce: &hex!("0046420eee8d56de35e2f7d5"),
        plaintext: &hex!("4835d489828325a0cb38a59fc29cfeedccae25f2e9c399281d9b7641fb609765"),
        aad: &hex!(
            "d51cedf9a30e476de37c90b2f60882193630c7497a921ab01590a26bce8cb247e3b5590e7b07b955956ca89c7a041988"
        ),
        ciphertext: &hex!("46eb31cd98b6cc3ecafe1cd1fc2d45fa693667cbd3a7d2c5f8c10296827ea83c"),
        tag: &hex!("36cd4e76dd0679887477bfb96cf1c5f6"),
    },
    TestVector {
        key: &hex!("0219f14b9ca6506c1388177c4ae6ee64ad2ac0256ebbf8c219b40df6e8571d70"),
        nonce: &hex!("3420a87c4b9b23ba81eb221e"),
        plaintext: &hex!("348f7a4ca944f252e4562c66dacf01fb10d70a3c8f5b280a2829567a2a94e47e"),
        aad: &hex!(
            "54dc2277b8d1aae660ffcc326e2c5d9e16b8ca17288601aacd02b3eea8bc5cc60718639aa189506b7b333b87da86e940"
        ),
        ciphertext: &hex!("58c92119bfb6ad53e387cac6728ce73b82e18f6e5bfbfca5f5acc370cd8c76a4"),
        tag: &hex!("e7f9e3e3dae6d0a3470d8f597291180c"),
    },
    TestVector {
        key: &hex!("87440ee7f6febf3e14ef0a917a87c5d61260fefc979eeaeac0a64662c98cb4f7"),
        nonce: &hex!("7c48bc75e58f21cc9989d691"),
        plaintext: &hex!("f8e40a6a985f424898a7996307a077c487406c5312eefe055ea5b17a4b22087b"),
        aad: &hex!(
            "e0c66e5db1c7665a015ba7e21e08ff3de5b4a5fcd5d35e41db7e97ccd0c3df657ae803c3529d375420ad75ac9621cea0"
        ),
        ciphertext: &hex!("5a118fc3dbdaf6bc9490d372b7623af76da7841bf9820a9c6624a15eff6a69c2"),
        tag: &hex!("0ddc2ae087d9b8ca2249ea5aa3dbd4c7"),
    },
    TestVector {
        key: &hex!("b12425796f63bf5435740f9039fa66367fc7702d675c61b2dec4435feeea07f8"),
        nonce: &hex!("f26727053e6d67c2d2bf1e69"),
        plaintext: &hex!("9df079d98a6e4dbe277a8545f4f6c19fe130f4a84bdd6b760a049fba21d4e99a"),
        aad: &hex!(
            "e50fca2e5a81ae56ca07f34c4b5da140d368cceab08494f5e28f746cbfefdc285b79b33cf4969fe618b77ab7baafe271"
        ),
        ciphertext: &hex!("845f00202e2e894516d8f4a4021430e531967098c9a94024c7113c9a1b91c8cd"),
        tag: &hex!("3566c75967ae00198e39ebe9f0ac697f"),
    },
    TestVector {
        key: &hex!("674dfb625b8b0ce1dadbbbcbf7e151c5b2cecf0a1bc4e07f4734f3a6792350cd"),
        nonce: &hex!("99e7b76e6686449616ad36c7"),
        plaintext: &hex!("0a744a72e536a0484db47091609228d803bcfa9a8daf579e3039e3645f7688e2"),
        aad: &hex!(
            "2ab1573e5a94ca2997590840bd9c62e6add55e4d3eac12c895d2ec637791caa41d46ed91e6064db627e1fbef71d31d01"
        ),
        ciphertext: &hex!("e550ee77069709f5199be3c618f2a4178e4d719ab73df41cbfe32c52777138ff"),
        tag: &hex!("134ac3fa8bd4af7ee836f4a3421d9e99"),
    },
    TestVector {
        key: &hex!("10c1de5f741560dae5be23e15649f0114db52949560bb6cdf2d4883247392ee1"),
        nonce: &hex!("7cf73c1472cd60d8d35fde51"),
        plaintext: &hex!("05becd366aebaa2e609f507dd2dd4433b2aba0634b0eb9a5bf7ded4cc8fbed72"),
        aad: &hex!(
            "d3fa8b6f607a20a18dd7eac85eabef69d4fb5a074d8e7d1bf15d07732ed80e020163b475f209c4b0cbfa00d65d1e82ef"
        ),
        ciphertext: &hex!("280f0c306e1a3aab8ff9ab3e4a9adc2e9ae4e4e1a06f190d11b3b4dc4280e4f3"),
        tag: &hex!("3bc8be845bf5ff844c07337c2cfd5f80"),
    },
    TestVector {
        key: &hex!("e8d6ab5e514645dd7e051b028f5bfe624c72f44f30279577365aea65d4a8a819"),
        nonce: &hex!("30b0d654ee5b79c2cfb24100"),
        plaintext: &hex!("19be7e0feedd402bf4b05995a38e5f423c033de016e3ae83ea8c3c1cba658e1e"),
        aad: &hex!(
            "082e534bf860d0061ec2dad34d6b0db8cba1c651f2c705356ff271e47365b0b18f8ddb3a3c2269b437fb0703c9ad367a"
        ),
        ciphertext: &hex!("8573800c737d2480b2885ce714ac6a15f23287b1d12949a3d76effbe82b593bd"),
        tag: &hex!("50110884292151f51213ccb2fe934d88"),
    },
    TestVector {
        key: &hex!("2d1eaf5e62ca80fd1515a811c0e4c045aba8c769df03d57f7493eb623ed8b941"),
        nonce: &hex!("abf190b05df2e6556cb34b47"),
        plaintext: &hex!("9c7cd522ed5c0af3e57da08d2653ef77eb973734f360572bbcb15a2a6cbd60b9"),
        aad: &hex!(
            "75ab9bd39c24e498a54d85a8b76a4126dc1879f2a30270a42609763e045a4021785b6134f283fd81c195c3188e78752d"
        ),
        ciphertext: &hex!("5fdfdaccb105e5408c375af8ca63a67afaba7ccbcd591acca9a86d92f92fd0f7"),
        tag: &hex!("49940b7610618b3a5cb3912339e06b3c"),
    },
    TestVector {
        key: &hex!("b6020677e098c59e19eacf26732473d843aafd6bf999c707bb08ab896406918d"),
        nonce: &hex!("807167ef2b84b32d1df4a94c"),
        plaintext: &hex!("3199d6b95d133ba5b7eadc420080a0b249c84f4960bd369d6bf9e313627cf670"),
        aad: &hex!(
            "06225d410ada3e04157da7e5481d7d9f2285845824aac0c0e033244ed4c1b19615354c224ba8b7093c5651d10ef952fe"
        ),
        ciphertext: &hex!("4618adbfa5ea4ee260e310140b385232b7c3ad46887aa2107f7dafffd85cda22"),
        tag: &hex!("2d76307bf55826dfeb58a171b6fa80e4"),
    },
    TestVector {
        key: &hex!("f75456c4918d0bea72f546a9a1e2db0b6ab9bcd9782b5eb1c2700e729921d666"),
        nonce: &hex!("c75b83134e7b9188e5800ffe"),
        plaintext: &hex!("f9a23abbd0f2b367ce16c2a0613cd293ac7e66cbe020eaeb5deb09d5031fd992"),
        aad: &hex!(
            "5ef46c9eb5865cab2c8a35f9c4c434614a6c9f1b5c479739f7434d3326cff1e70b0d2877c084a71c7a9d33d258d304bb"
        ),
        ciphertext: &hex!("56e4efe6c0944153b65ed4909845219842b9b88f54d8d8394051132afb95d391"),
        tag: &hex!("255e2c8c43f8979c440c3581bff6cf65"),
    },
    TestVector {
        key: &hex!("9831c5c12e53e8a961642e93ddb2e13a38506acd0cf422e6ad9fbaeabce7b3f2"),
        nonce: &hex!("bff29de3d6869e5fa75b96f9"),
        plaintext: &hex!("b1edbed58ed34e99f718db0608e54dd31883baec1c8a0799c4ff8a5dad468de4"),
        aad: &hex!(
            "67ebeecb74cc81fdfee8065f8b1c1f5012bf788953bec9525e896611b827084a8e6baa0ce40ee70bc699b152bc6ed903"
        ),
        ciphertext: &hex!("13845db7e33bab1f5766a7fadfb942748e779753d97f143e645ccfcbd7c23b23"),
        tag: &hex!("10dbe8a3e1901c8b88b0ab1441664d32"),
    },
    TestVector {
        key: &hex!("a02c2d4a43f0f7f1db57c07f13f07f588edfe069a9d83c9b76e9511946c4fc48"),
        nonce: &hex!("84677438592dcaf683d08a67"),
        plaintext: &hex!("ad5a884dad20ffa88794c4fca39f2ca01c6f67657ab38e5cf86ac5597318ef07"),
        aad: &hex!(
            "d5dea0cd6080af49a1c6b4d69ace674a622f84f9f190b2db8a22e084a66500b52ff20a8d04f62a7aeaedb67e2258598c"
        ),
        ciphertext: &hex!("83da16ae07ee0e885484c1330a6255a6e7ac22915c63cbefaabc6f9f059dd69d"),
        tag: &hex!("42c4a270705493d85ad7bbcfda86dffb"),
    },
    TestVector {
        key: &hex!("feba412b641bc762bfa79ef17c3ea16e5630605470db096e36ffd33813641ace"),
        nonce: &hex!("e3633f21e7c63a459d5d1670"),
        plaintext: &hex!("9326572bd33551322ca42fcfb7cef8be41d78725f392c34907ecd1fe5572bff1"),
        aad: &hex!(
            "b7ee0233863b0e185b2f46181eb5fc0718832e1e76e7d4115a4c1f7e998c41319ccef44f5db89e8c5f077bd553d7bf42"
        ),
        ciphertext: &hex!("5019ea98cc9dc9368432c6d58f9e144f55446e763c0a8b4d8a6ce26f3dd95260"),
        tag: &hex!("1010beb9cd6e9b611280a5395f08bca9"),
    },
    TestVector {
        key: &hex!("21bd5691f7af1ce765f099e3c5c09786936982834efd81dd5527c7c322f90e83"),
        nonce: &hex!("36a59e523df04bc7feb74944"),
        plaintext: &hex!("77e539dfdab4cfb9309a75c2ee9f9e9aa1b4651568b05390d73da19f12ccbe78"),
        aad: &hex!(
            "48aef5872f67f524b54598781c3b28f9cbcf353066c3670370fca44e132761203100b5e6c7352a930f7e9cbf28a8e1ce"
        ),
        ciphertext: &hex!("c21483731f7fe1b8a17d6e133eda16db7d73ddd7e34b47eec2f99b3bbc9669aa"),
        tag: &hex!("15f9265bc523298cefb20337f878b283"),
    },
    TestVector {
        key: &hex!("26bf255bee60ef0f653769e7034db95b8c791752754e575c761059e9ee8dcf78"),
        nonce: &hex!("cecd97ab07ce57c1612744f5"),
        plaintext: &hex!("96983917a036650763aca2b4e927d95ffc74339519ed40c4336dba91edfbf9ad"),
        aad: &hex!(
            "afebbe9f260f8c118e52b84d8880a34622675faef334cdb41be9385b7d059b79c0f8a432d25f8b71e781b177fce4d4c57ac5734543e85d7513f96382ff4b2d4b95b2f1fdbaf9e78bbd1db13a7dd26e8a4ac83a3e8ab42d1d545f"
        ),
        ciphertext: &hex!("e34b1540a769f7913331d66796e00bdc3ee0f258cf244eb7663375cc5ad6c658"),
        tag: &hex!("3841f02beb7a7fca7e578922d0a2f80c"),
    },
    TestVector {
        key: &hex!("74ce3121c18bbff4756ad10d0f293bb1ea3f93490daad0249cd3b05e223c9747"),
        nonce: &hex!("81107afb4c264f65ae0002b1"),
        plaintext: &hex!("7a133385ead593c3907806bec12240943f00a8c3c1b0ac73b8b81af2d3192c6f"),
        aad: &hex!(
            "f00847f848d758494afd90b6c49375e0e76e26dcba284e9a608eae33b87ad2deac28ccf40d2db154bbe10dc0fd69b09c9b8920f0f74ea62dd68df275074e288e76a290336b3bf6b485c0159525c362092408f51167c8e59e218f"
        ),
        ciphertext: &hex!("64bd17f3e8f71a4844b970d4ebc119961812efb9015b818e8d88b906d5efbd76"),
        tag: &hex!("46d0e42aa046237efee17eab6d9cfb75"),
    },
    TestVector {
        key: &hex!("4c669a1969c97d56da30a46236c15407e06aada686205eed3bd7796b02c97a4b"),
        nonce: &hex!("0a07758d5ad44766e051da6c"),
        plaintext: &hex!("cd59bb307be76f11304f69ac8b151e1628ac61dec81086e7f24fd5bd83df8856"),
        aad: &hex!(
            "0b8277114cbf7ee16c9bbda1ab40419a02e469ebb295883f0a833c3cb755ded44a3c410034a201f7d91b43519fbabb55b974834be5d5afc7aea7c84b44a14e8e16dd68a3e8cc79ad2bf76d0ceb33d58ddb6378b45681ceaa0f2f"
        ),
        ciphertext: &hex!("bc62ce0b23cf4aa8e16b4450c8ab8c629a53949f01e68b875ecc5c45ff6d3ab0"),
        tag: &hex!("5ffeda728914031006f271c3d9986f2d"),
    },
    TestVector {
        key: &hex!("a23296632913051e438114deb782fb955b75acc35e86e7e9fdaf4e9025b87f12"),
        nonce: &hex!("ad50db40f80f15214e43ffd7"),
        plaintext: &hex!("b71116cc27b5a5844d9b51a4a720cb3f06d55d6aaeaeaf921236424db8617204"),
        aad: &hex!(
            "a6f96f5a89bfd8c8f34cd07045270d80e58ea62f1f0b10f2506a954f272af0bc71df96ad3fa8eed52c45e0b868091dc4f75d9e0eaf15a0a858a71bf7036c5607110cbfe47ad9b6d02e942fcfae88d4c792a1f824e60e3cf98a37"
        ),
        ciphertext: &hex!("8e9e4b0ac93ab8e73688d6b4723d8c5ef399ead72246c7aa7a0783a8bfe29936"),
        tag: &hex!("b7dea91e4b357ce805edeea3f91392d2"),
    },
    TestVector {
        key: &hex!("4036a07bdd4e10eb545f3d9124c9f766d2d0c8c59fc0d5835ac55dcfaebfc3a1"),
        nonce: &hex!("815828fbb964497cdadccaad"),
        plaintext: &hex!("717f22faff8066182e46d32dbac7831ec24272871c45c7c12ca779f868e7739a"),
        aad: &hex!(
            "0bc0e3931388bcb091463bae2989a93bde103bc14fc5d39f9448ca90367e86336b188f73218b2b0ab72a9a564ad5ff32544c5afeacecadfa55d2fb66925a88299dbf58f425cf49e31f42ac4edace743fdf9680d20ec845afc278"
        ),
        ciphertext: &hex!("e8c3b0342964c7a71f084d44ba2f93742bccd9821b30087d11b53bbe8b085808"),
        tag: &hex!("86ddd9c469849cb6b100c339ca62717d"),
    },
    TestVector {
        key: &hex!("714bc3ba3839ac6707863a40aa3db5a2eebcb38dc6ec6d22b083cef244fb09f7"),
        nonce: &hex!("2cfe1c51d894e5ef2f5a2c3c"),
        plaintext: &hex!("0cc4a18bbfea87de0ac3446c777be38ca843d16f93be2c12c790fda4de94c9bf"),
        aad: &hex!(
            "84e3d46af2ecb717a39024d62bbc24d119f5aff57569dfef94e7db71ad5aff864abacdc5f8554e18ed5129cfb3366d349c52b3d1a111b867e8772140749e7f33e2e64259968486e32f047d21120da73c77757c4595ccac1b5713"
        ),
        ciphertext: &hex!("0857c8fb93412fde69bad287b43deea36506d7ee061d6844d00a7e77418f702f"),
        tag: &hex!("24a9e5290957074807d55ad705adaa89"),
    },
    TestVector {
        key: &hex!("2f93b5a37be1a43853bf1fd578061d0744e6bd89337cde20177d1e95a2b642c4"),
        nonce: &hex!("52b6d91557ae15aa792ce4b7"),
        plaintext: &hex!("0fcaa316a135d81052509dd85f688aed2e5fd4261e174f435cf1c4115aa6f354"),
        aad: &hex!(
            "992ba9efa287a5c3e5177bd4931af498982a1728b56b3d7c4b28476905e29f83326c4f3223a28844fc9b9d84d4f6cd859074aff647a35dde28e1ee889faab3bb9c09a4c3fbf2a16460d48a40dc53378d4673f4325e6aa3992a71"
        ),
        ciphertext: &hex!("f99774cef3c15af33cda3cb449cd335ffe4f27435edf83aff4a4f4c2d2df6647"),
        tag: &hex!("c5e09b83b1c2cc81e48a1f7c62b7bb35"),
    },
    TestVector {
        key: &hex!("531ca845af7bf731c49c3136407322b1c0f6b32b8eaebf03744b2edc1202d096"),
        nonce: &hex!("baf13b85202bbfc899fc73f7"),
        plaintext: &hex!("d4e9783f537c738200e7ba7526605f359a98c9f10cafaa2f433c40f3e5081a36"),
        aad: &hex!(
            "e2ba9cf548b4f6fb206f224250d85af327fde8d08916686ae770203dc29c694f8902b02222fd287f28ce6091006368c3949bea2937ff0bdedb7dbbd013ccf0a15ee0af8c56fe211b7c311e182f27707f59e09492b3604e80c6c5"
        ),
        ciphertext: &hex!("642f544929202128a783b985d36f60964c7d78e1d41f5d1bfe27de3ae0180df3"),
        tag: &hex!("e333528c59ee1909750ed72fd1309ee1"),
    },
    TestVector {
        key: &hex!("3add17568daa9d441aa7a89bf88fa4e6998a921d57e494a254080445bc9b6f35"),
        nonce: &hex!("b290f4a52496380218c3dcf5"),
        plaintext: &hex!("2c6908cb34215f89a3f3a3c892e8887f2efa496a15ab913fc7d34cc70c0dff79"),
        aad: &hex!(
            "0bc9cc13eb2890aa60515c2297a99f092f6e516236c0dec9f986ea98b8a180680f2c6c20bd4354c33433a4c6f6a25e632f90ebef3a383c3592268b483eebf5f5db006929e7987edbcac4755d3afd1cdf9b02954ebd4fef53d5f6"
        ),
        ciphertext: &hex!("2cf3beae94fd5e6a4126a8ec8a7166b0aacb8b8bbce45d6106b78d3456d05149"),
        tag: &hex!("ce1509b1bd5c47a593702618b0d79f6c"),
    },
    TestVector {
        key: &hex!("1c1dcfd4c4cc4beb71d6e368f739d8e681dfe48fbae39728386c9dfc08825743"),
        nonce: &hex!("0deceb69ce0dc776a3a71b4c"),
        plaintext: &hex!("b12700258ace7b16e40f4e86886892837168b256a170937a3b89063a9a0d68f7"),
        aad: &hex!(
            "a3af2db672292431fa8ee1fa5b197593b13e58a68c4129401d0942474d5f4cbe62093aaa5453f6d355d2f4b6dc8abde58ce863d1be5f9ecf39730a49565b3b6882a0a641c0b5d156a4107309dd150fd1f1634ea4e5100b3d4f88"
        ),
        ciphertext: &hex!("3ea7f1c0d613323e095558ddde53247420fa0eef17997a1e9c5ba93d5f24c46f"),
        tag: &hex!("70534a87c258905d35806f4439f6906e"),
    },
    TestVector {
        key: &hex!("f2724153aac9d50f350878d3c498bc3dd782d90cce5cce4ae14126c0e1fbb3cf"),
        nonce: &hex!("1c07b61c5316659bad65cca9"),
        plaintext: &hex!("067ccbd0206f1f05d2872210dc5717a0585e8195d72afd0c77da11b9b3710e44"),
        aad: &hex!(
            "e69db7fcd3b590a6d32052612034036d5c8bffa5e5e9b742ffe75a9fbba89dd576dec08154cf4e6d36f0fdd4419bdf50adc1974a80ea313421c926dffa87565b4bd0c1e84f2ff305af91877f830f145bb13dfa7efa5e3aa682e6"
        ),
        ciphertext: &hex!("9aba433eef383466a1291bd486c3ce5e0ed126010e0a77bf037c5eaed2c72460"),
        tag: &hex!("f30a155e35400bb0540883e8e09b4afd"),
    },
    TestVector {
        key: &hex!("a2544eb2047c97cfcaf0ec1427c5df395472285233a93ffccda8fee660aced56"),
        nonce: &hex!("a751bea3c769bb5db25ab109"),
        plaintext: &hex!("b9514cc01a357605918f9cc19123dcc8db328c605ca0eb9d69d871afeea1dcfb"),
        aad: &hex!(
            "eb9e09884de1454d6aeb0d6c82375f2428992031ea6cabf6a29aa6a4de49a353e4ffae043dad18ae651b20b7bca13f5c327ca9f132014bfa86e716d4724e05a1ef675521a6607a536756e6a8c16bb885b64815f1eb5ec282ce8e"
        ),
        ciphertext: &hex!("cb442b17088f6ac5f24c7a04f0050559386f3a57131b92a54142c7a556fdb935"),
        tag: &hex!("5f80c5c0cdf0c7890bfd1fbd58c33081"),
    },
    TestVector {
        key: &hex!("ceb057782efb1e85d805448af946a9b4d4128bf09a12473cce1e8ef8bfd2869d"),
        nonce: &hex!("406f9730e9b1e421e428439b"),
        plaintext: &hex!("0815723d5367b1328cac632fa26e23f2b814a1d59a2971d94d02ebd7ecf5c14a"),
        aad: &hex!(
            "0772ae00e1ca05d096cf533fd3de2818ac783edfca0eee7686a6290f3357481e883fb2f895b9a4f4004c56b8a1265242cfdf1fb4af7edc41ed78c5f4ffe9c4080d4a17318f9c56ecdb3a06f3c748535387d56a096943a76d46f6"
        ),
        ciphertext: &hex!("9d82355d8e460896201be15fd95fed48a8524666d987ab078550883034d0253c"),
        tag: &hex!("a0bee8ac0e636d64d3b1eb33fd6f21d4"),
    },
    TestVector {
        key: &hex!("7dbdbdfe36d4936940ad6d6f76c67c2851a0477f0aa7d6797bfdf2b7878ef7e0"),
        nonce: &hex!("bc672b224b4b6b91fc3fd697"),
        plaintext: &hex!("dfea463d35f0fa20487b606d6ccfd422a5b707f16527b422bf1d68a77db67e9c"),
        aad: &hex!(
            "faacb84ec7cfadd731de2f7c0892d7e38cbfb782b48412331af0b3eab602a722cad1069dea0052beb5ca70e2ee476c340c6193bcc60f939aabe446bf3ce958fe11a2ffc90241f0a7e4e274f0c1441def795893895bd848bf0f0e"
        ),
        ciphertext: &hex!("0ddc2281b1fcb904864a43657bc72357cf73fc1f16520caad7cddde10f846bd9"),
        tag: &hex!("9d96699450aa9707695e5de56597101b"),
    },
    TestVector {
        key: &hex!("187214df6e2d80ee8e9aae1fc569acd41589e952ddcbe8da018550d103767122"),
        nonce: &hex!("56db334422b6c5e93460d013"),
        plaintext: &hex!("53355283186719a9146c7305e3d1959a11ccf197570b855a43cbc7563a053c73"),
        aad: &hex!(
            "cbedb7ccfbf56dfd72e530bfe16b4f5aac48a90204bcb7a8cae1046010882cfc8b526e7562a7880914e61b60cbd605165242737d85eeed583c98cab3443874e5989ec9cde001adf7de9c9967de5178f75b8412b0c4d6fec5af72"
        ),
        ciphertext: &hex!("c2262585966bc9c23dc7cc1059d060211e86f3b3161d38b153635fbea4a28c05"),
        tag: &hex!("a94297c584dfcd10ee5df19a2ee5c3d2"),
    },
    TestVector {
        key: &hex!("1fded32d5999de4a76e0f8082108823aef60417e1896cf4218a2fa90f632ec8a"),
        nonce: &hex!("1f3afa4711e9474f32e70462"),
        plaintext: &hex!(
            "06b2c75853df9aeb17befd33cea81c630b0fc53667ff45199c629c8e15dce41e530aa792f796b8138eeab2e86c7b7bee1d40b0"
        ),
        aad: b"",
        ciphertext: &hex!(
            "91fbd061ddc5a7fcc9513fcdfdc9c3a7c5d4d64cedf6a9c24ab8a77c36eefbf1c5dc00bc50121b96456c8cd8b6ff1f8b3e480f"
        ),
        tag: &hex!("30096d340f3d5c42d82a6f475def23eb"),
    },
    TestVector {
        key: &hex!("b405ac89724f8b555bfee1eaa369cd854003e9fae415f28c5a199d4d6efc83d6"),
        nonce: &hex!("cec71a13b14c4d9bd024ef29"),
        plaintext: &hex!(
            "ab4fd35bef66addfd2856b3881ff2c74fdc09c82abe339f49736d69b2bd0a71a6b4fe8fc53f50f8b7d6d6d6138ab442c7f653f"
        ),
        aad: b"",
        ciphertext: &hex!(
            "69a079bca9a6a26707bbfa7fd83d5d091edc88a7f7ff08bd8656d8f2c92144ff23400fcb5c370b596ad6711f386e18f2629e76"
        ),
        tag: &hex!("6d2b7861a3c59ba5a3e3a11c92bb2b14"),
    },
    TestVector {
        key: &hex!("fad40c82264dc9b8d9a42c10a234138344b0133a708d8899da934bfee2bdd6b8"),
        nonce: &hex!("0dade2c95a9b85a8d2bc13ef"),
        plaintext: &hex!(
            "664ea95d511b2cfdb9e5fb87efdd41cbfb88f3ff47a7d2b8830967e39071a89b948754ffb0ed34c357ed6d4b4b2f8a76615c03"
        ),
        aad: b"",
        ciphertext: &hex!(
            "ea94dcbf52b22226dda91d9bfc96fb382730b213b66e30960b0d20d2417036cbaa9e359984eea947232526e175f49739095e69"
        ),
        tag: &hex!("5ca8905d469fffec6fba7435ebdffdaf"),
    },
    TestVector {
        key: &hex!("aa5fca688cc83283ecf39454679948f4d30aa8cb43db7cc4da4eff1669d6c52f"),
        nonce: &hex!("4b2d7b699a5259f9b541fa49"),
        plaintext: &hex!(
            "c691f3b8f3917efb76825108c0e37dc33e7a8342764ce68a62a2dc1a5c940594961fcd5c0df05394a5c0fff66c254c6b26a549"
        ),
        aad: b"",
        ciphertext: &hex!(
            "2cd380ebd6b2cf1b80831cff3d6dc2b6770778ad0d0a91d03eb8553696800f84311d337302519d1036feaab8c8eb845882c5f0"
        ),
        tag: &hex!("5de4ef67bf8896fbe82c01dca041d590"),
    },
    TestVector {
        key: &hex!("1c7690d5d845fceabba227b11ca221f4d6d302233641016d9cd3a158c3e36017"),
        nonce: &hex!("93bca8de6b11a4830c5f5f64"),
        plaintext: &hex!(
            "3c79a39878a605f3ac63a256f68c8a66369cc3cd7af680d19692b485a7ba58ce1d536707c55eda5b256c8b29bbf0b4cbeb4fc4"
        ),
        aad: b"",
        ciphertext: &hex!(
            "c9e48684df13afccdb1d9ceaa483759022e59c3111188c1eceb02eaf308035b0428db826de862d925a3c55af0b61fd8f09a74d"
        ),
        tag: &hex!("8f577e8730c19858cad8e0124f311dd9"),
    },
    TestVector {
        key: &hex!("dbdb5132f126e62ce5b74bf85a2ac33b276588a3fc91d1bb5c7405a1bf68418b"),
        nonce: &hex!("64f9e16489995e1a99568118"),
        plaintext: &hex!(
            "b2740a3d5647aa5aaeb98a2e7bbf31edaea1ebacd63ad96b4e2688f1ff08af8ee4071bf26941c517d74523668ca1f9dfdbcaab"
        ),
        aad: b"",
        ciphertext: &hex!(
            "e5fec362d26a1286b7fd2ec0fa876017437c7bce242293ff03d72c2f321d9e39316a6aa7404a65ccd84890c2f527c1232b58d5"
        ),
        tag: &hex!("dfa591ee2372699758d2cc43bfcbd2ba"),
    },
    TestVector {
        key: &hex!("8433a85f16c7c921476c83d042cb713eb11a83fc0cffe31dde97907f060b4ee9"),
        nonce: &hex!("55ffc85ffd1cdea8b8c48382"),
        plaintext: &hex!(
            "23bc3983ba5b3be91c8a6aa148a99995241ee9e82ce44e1184beb742affbe48f545c9a980480cf1fab758a46e4711ea9267466"
        ),
        aad: b"",
        ciphertext: &hex!(
            "2f4bdc7b8b8cec1863e3145871554778c43963b527f8413bb9779935c138a34d86d7c76a9e6af689902f316191e12f34126a42"
        ),
        tag: &hex!("7dc63156b12c9868e6b9a5843df2d79e"),
    },
    TestVector {
        key: &hex!("5d7bf55457929c65e4f2a97cbdcc9b432405b1352451ccc958bceebce557491d"),
        nonce: &hex!("f45ae70c264ed6e1cc132978"),
        plaintext: &hex!(
            "ba5ac2a16d84b0df5a6e40f097d9d44bf21de1fcec06e4c7857463963e5c65c936d37d78867f253ce25690811bf39463e5702a"
        ),
        aad: b"",
        ciphertext: &hex!(
            "47c16f87ebf00ba3e50416b44b99976c2db579423c3a3420479c477cd5ef57621c9c0cee7520acb55e739cc5435bc8665a2a0c"
        ),
        tag: &hex!("456054ecb55cf7e75f9543def2c6e98c"),
    },
    TestVector {
        key: &hex!("595f259c55abe00ae07535ca5d9b09d6efb9f7e9abb64605c337acbd6b14fc7e"),
        nonce: &hex!("92f258071d79af3e63672285"),
        plaintext: &hex!(
            "a6fee33eb110a2d769bbc52b0f36969c287874f665681477a25fc4c48015c541fbe2394133ba490a34ee2dd67b898177849a91"
        ),
        aad: b"",
        ciphertext: &hex!(
            "bbca4a9e09ae9690c0f6f8d405e53dccd666aa9c5fa13c8758bc30abe1ddd1bcce0d36a1eaaaaffef20cd3c5970b9673f8a65c"
        ),
        tag: &hex!("26ccecb9976fd6ac9c2c0f372c52c821"),
    },
    TestVector {
        key: &hex!("251227f72c481a7e064cbbaa5489bc85d740c1e6edea2282154507877ed56819"),
        nonce: &hex!("db7193d9cd7aeced99062a1c"),
        plaintext: &hex!(
            "cccffd58fded7e589481da18beec51562481f4b28c2944819c37f7125d56dceca0ef0bb6f7d7eeb5b7a2bd6b551254e9edff3a"
        ),
        aad: b"",
        ciphertext: &hex!(
            "1cc08d75a03d32ee9a7ae88e0071406dbee1c306383cf41731f3c547f3377b92f7cc28b3c1066601f54753fbd689af5dbc5448"
        ),
        tag: &hex!("a0c7b7444229a8cfef24a31ee2de9961"),
    },
    TestVector {
        key: &hex!("f256504fc78fff7139c42ed1510edf9ac5de27da706401aa9c67fd982d435911"),
        nonce: &hex!("8adcf2d678abcef9dd45e8f9"),
        plaintext: &hex!(
            "d1b6db2b2c81751170d9e1a39997539e3e926ca4a43298cdd3eb6fe8678b508cdb90a8a94171abe2673894405eda5977694d7a"
        ),
        aad: b"",
        ciphertext: &hex!(
            "76205d63b9c5144e5daa8ac7e51f19fa96e71a3106ab779b67a8358ab5d60ef77197706266e2c214138334a3ed66ceccb5a6cd"
        ),
        tag: &hex!("c1fe53cf85fbcbff932c6e1d026ea1d5"),
    },
    TestVector {
        key: &hex!("21d296335f58515a90537a6ca3a38536eba1f899a2927447a3be3f0add70bea5"),
        nonce: &hex!("2be3ad164fcbcf8ee6708535"),
        plaintext: &hex!(
            "ad278650092883d348be63e991231ef857641e5efc0cab9bb28f360becc3c103d2794785024f187beaf9665b986380c92946a7"
        ),
        aad: b"",
        ciphertext: &hex!(
            "b852aeba704e9d89448ba180a0bfde9e975a21cc073d0c02701215872ed7469f00fe349294ba2d72bf3c7780b72c76101ba148"
        ),
        tag: &hex!("bdd6d708b45ae54cd8482e4c5480a3c1"),
    },
    TestVector {
        key: &hex!("d42380580e3491ddfbc0ec32424e3a281cbe71aa7505ff5ab8d24e64fbe47518"),
        nonce: &hex!("fbed88de61d605a7137ffeb2"),
        plaintext: &hex!(
            "4887a6ef947888bf80e4c40d9769650506eb4f4a5fd241b42c9046e3a2cf119db002f89a9eba1d11b7a378be6b27d6f8fc86c9"
        ),
        aad: b"",
        ciphertext: &hex!(
            "87aa27f96187ce27e26caf71ba5ba4e37705fd86ca9291ea68d6c6f9030291cdbff58bff1e6741590b268367e1f1b8c4b94cd4"
        ),
        tag: &hex!("d1690a6fe403c4754fd3773d89395ecd"),
    },
    TestVector {
        key: &hex!("5511727ecd92acec510d5d8c0c49b3caacd2140431cf51e09437ebd8ca82e2ce"),
        nonce: &hex!("ae80d03696e23464c881ccff"),
        plaintext: &hex!(
            "184b086646ef95111ccb3d319f3124f4d4d241f9d731ce26662ea39e43457e30b0bd739b5d5dbceb353ce0c3647a3a4c87e3b0"
        ),
        aad: b"",
        ciphertext: &hex!(
            "aa28cb257698963dfc3e3fe86368d881ac066eb8ee215a7c0ed72e4d081db0b940071e2e64ff6204960da8e3464daf4cb7f37b"
        ),
        tag: &hex!("c1578aa6e3325ee4b5e9fb9ee62a7028"),
    },
    TestVector {
        key: &hex!("d48f3072bbd535a2df0a2864feb33b488596cd523ad1623b1cefe7b8cbefcf4a"),
        nonce: &hex!("bbf2a537d285444d94f5e944"),
        plaintext: &hex!(
            "060c585bd51539afdd8ff871440db36bfdce33b7f039321b0a63273a318bd25375a2d9615b236cfe63d627c6c561535ddfb6bd"
        ),
        aad: b"",
        ciphertext: &hex!(
            "993d5d692c218570d294ab90d5f7aa683dc0e470efac279a776040f3b49386813f68b0db6a7aef59025cc38520fb318a1eac55"
        ),
        tag: &hex!("8cd808438a8f5b6a69ff3ae255bf2cb2"),
    },
    TestVector {
        key: &hex!("5fe01c4baf01cbe07796d5aaef6ec1f45193a98a223594ae4f0ef4952e82e330"),
        nonce: &hex!("bd587321566c7f1a5dd8652d"),
        plaintext: &hex!(
            "881dc6c7a5d4509f3c4bd2daab08f165ddc204489aa8134562a4eac3d0bcad7965847b102733bb63d1e5c598ece0c3e5dadddd"
        ),
        aad: &hex!("9013617817dda947e135ee6dd3653382"),
        ciphertext: &hex!(
            "16e375b4973b339d3f746c1c5a568bc7526e909ddff1e19c95c94a6ccff210c9a4a40679de5760c396ac0e2ceb1234f9f5fe26"
        ),
        tag: &hex!("abd3d26d65a6275f7a4f56b422acab49"),
    },
    TestVector {
        key: &hex!("885a9b124137e40bd0f697771317e401ce36327e61a8f9d0b80f4798f30a731d"),
        nonce: &hex!("beebc2f5a26fd2cab1e9c395"),
        plaintext: &hex!(
            "427ec568ad8367c202f5d9999240f9994cc113500154f7f49e9ca27cc8154143b855238bca5c7bd6d9852b4eebd41e4eb98f16"
        ),
        aad: &hex!("2e8bdde32258a5fcd8cd21037d0545eb"),
        ciphertext: &hex!(
            "a1d83aab6864db463d9d7c22419462bde0740355c1147c62b4c4f23ceeaf65b16b873b1cc7e698dff6e3d19cf9da33e8cbcba7"
        ),
        tag: &hex!("4fdbfd5210afa3556ec0fdc48b98e1eb"),
    },
    TestVector {
        key: &hex!("21c190e2b52e27b107f7a24b913a34bd5b7022060c5a4dec9ab289ff8ae67e2d"),
        nonce: &hex!("b28a61e6c1dfa7f76d086063"),
        plaintext: &hex!(
            "4e1b9528cf46b1dd889858d3904d41d3174dcb225923f923d80adbfe6eec144b1d4eb3690d0b8519c99beaee25bb50fd2d148f"
        ),
        aad: &hex!("d80657377ddbbed1f9b8d824b3c4d876"),
        ciphertext: &hex!(
            "7126fa807aa6b61a60958fe4cc8682bb256e5bbdc499d04a6caa81b23f9e67d3da4cf1994b5a8ecc7bce641864d0519a6509cd"
        ),
        tag: &hex!("d3e96568f2cd1a48771ee4f67ad042c1"),
    },
    TestVector {
        key: &hex!("11c33ae37680130c51ed11bfaf0fcb6ed4fc7d903ff432b811763d2c7ef83a33"),
        nonce: &hex!("0f224d26dbf632cebdce3b8b"),
        plaintext: &hex!(
            "f8a2affe5a7e67f2c62622e4a56804b48e529d1faf9096f94409224129921ce46aed898dd5391746e8170e05f91e0524166625"
        ),
        aad: &hex!("dee803732ff662cba9f861227f8b67cf"),
        ciphertext: &hex!(
            "3856558375c363b25e8f9e9e2eb63cf0e76a1c6e228893c7b22da4a69b682528b4a4ca2b99e7a537390e2d1e05a68f3e39c4e9"
        ),
        tag: &hex!("9b12691b2002ca9227035c68ea941ef3"),
    },
    TestVector {
        key: &hex!("3b291794fbb9152c3e4f4de4608a9137d277bd651f97e738afaa548d97b4ec60"),
        nonce: &hex!("4d1c69c6da96c085d31422ba"),
        plaintext: &hex!(
            "21b3ca1f47a0c7f6ebd097eda69d9e5b5fbf5c24d781658003cfd443ae7096be19e1cd3c14fe9738efb00847697fccb466ae1b"
        ),
        aad: &hex!("f3a5fa61a4e987413a8fab4aa51d895d"),
        ciphertext: &hex!(
            "6c1439cd2cb564e7944fd52f316e84aeffc3fd8024df5a7d95a87c4d31a0f8ea17f21442c709a83b326d067d5f8e3005ebe22a"
        ),
        tag: &hex!("e58048f2c1f806e09552c2e5cdf1b9d9"),
    },
    TestVector {
        key: &hex!("8e7a8e7b129326e5410c8ae67fbd318de1909caba1d2b79210793c6b2c6e61c7"),
        nonce: &hex!("8e48513fdd971861ef7b5dc3"),
        plaintext: &hex!(
            "ef6b4145910139293631db87a0d7782a1d95db568e857598128582e8914b4fa7c03c1b83e5624a2eb4c340c8ad7e6736a3e700"
        ),
        aad: &hex!("80bb66a4727095b6c201fb3d82b0fcf5"),
        ciphertext: &hex!(
            "e302687c0548973897a27c31911fc87ee93d8758c4ded68d6bd6415eaaf86bcc45fa6a1ef8a6ae068820549b170405b3fc0925"
        ),
        tag: &hex!("ff5c193952558e5a120e672f566be411"),
    },
    TestVector {
        key: &hex!("d687e0262f7af2768570df90b698094e03b668ce6183b6c6b6ca385dcd622729"),
        nonce: &hex!("50f6904f2d8466daa33c2461"),
        plaintext: &hex!(
            "79e3067d94464e019a7c8af10b53adf5b09426d35f2257c3cbaffe1ff720565c07e77aeef06f9d03a2353053992073a4ed1fc8"
        ),
        aad: &hex!("e8fa99432929d66f10205ad3e9592151"),
        ciphertext: &hex!(
            "18f6e6aeecc8dc5a3d0b63a2a8b7bfaf695bd9c49a7392dbfa8ed44771eebe27f94589d8a430da4cf03a8693bc7525e1fcac82"
        ),
        tag: &hex!("3c864eaa1b0ae44a7f0ad9ba287ba800"),
    },
    TestVector {
        key: &hex!("26dc5ce74b4d64d1dc2221cdd6a63d7a9226134708299cd719a68f636b6b5ebd"),
        nonce: &hex!("0294c54ff4ed30782222c834"),
        plaintext: &hex!(
            "ae4c7f040d3a5ff108e29381e7a0830221d5378b13b87ef0703c327686d30af004902d4ddb59d5787fecea4731eaa8042443d5"
        ),
        aad: &hex!("2a9fb326f98bbe2d2cf57bae9ecbeff7"),
        ciphertext: &hex!(
            "9601aec6bc6e8a09d054a01e500a4e4cdcc7c2cf83122656be7c26fc7dc1a773a40be7e8a049a6cdf059e93a23ca441ef1ca96"
        ),
        tag: &hex!("b620a8a0c8fe6117f22735c0ca29434c"),
    },
    TestVector {
        key: &hex!("7fa0644efc7f2e8df4b311f54ba8b8c975b2c2aa97962f8ca8a322541bedaa9d"),
        nonce: &hex!("5e774e45a07eeb9721734412"),
        plaintext: &hex!(
            "84d1c75455e4c57419a9d78a90efc232c179517fe94aff53a4b8f7575db5af627f3d008006f216ecfc49ab8da8927ff5dc3959"
        ),
        aad: &hex!("6ad673daa8c412bf280ea39ba0d9b6d4"),
        ciphertext: &hex!(
            "e2f00b5a86b3dec2b77e54db328c8d954d4b716f9735e5798b05d65c512674d56e88bda0d486685a45d5c249719884329e3297"
        ),
        tag: &hex!("0ce8eb54d5ad35dd2cb3fa75e7b70e33"),
    },
    TestVector {
        key: &hex!("91d0429f2c45cf8ab01d50b9f04daaaccbe0503c9f115f9457c83a043dc83b23"),
        nonce: &hex!("34401d8d922eebac1829f22e"),
        plaintext: &hex!(
            "d600d82a3c20c94792362959de440c93119a718ac749fa88aa606fc99cb02b4ca9ba958d28dc85f0523c99d82f43f58c5f979b"
        ),
        aad: &hex!("1b29de9321aebc3ff9d1c2507aee80e9"),
        ciphertext: &hex!(
            "84cbc9936eb7270080bb7024780113d064eccb63d3da0bd6bce4f8737d28304bfb6102f3ae9c394cc6452633fc551582bbfe1d"
        ),
        tag: &hex!("e132dc8a31d21f24ea0e69dfb6b26557"),
    },
    TestVector {
        key: &hex!("44e6411b9fbfcef387d0ca07b719181c7567e27dba59e8e1c3cc1763cfeaca04"),
        nonce: &hex!("25a1cfd97bd8e63de5d65974"),
        plaintext: &hex!(
            "db28a592b1f3603c287991a69cc64eacdd62046445a8ba4067575f12553de155d06a9b40ddf58fec56c8171687b9cb54b1f346"
        ),
        aad: &hex!("4b1751b074ab649d27fd3f2c4d7ee33a"),
        ciphertext: &hex!(
            "36bf6bb761b2248fe71a620e34e9d18e12a74ca42c9a9a21d30345995a83eb44bcae3c67c020730cd8d5e51a741694cc396469"
        ),
        tag: &hex!("e69ebf80a88d6eca41ae87cdcab4e1f2"),
    },
    TestVector {
        key: &hex!("a94bfcefae90f9078860db80ccc50819eadf7cce29df3279f94f5eea97009ef2"),
        nonce: &hex!("f481bcb7f5da296e9454ff78"),
        plaintext: &hex!(
            "97d0c7dfcab32a386f51d92e89333ec84eecd552e68d14cf48b75067bf0e1946ad03a5d063b852ca053c929088af45d0884a88"
        ),
        aad: &hex!("9f80d845577818df9ba984ee552ae203"),
        ciphertext: &hex!(
            "18a1c9bfe1b1dfdd06e465df347c1e942b37b3e48cb0c905841a593b5b0d0330feb3b8970dbc9429252a897f0f8e12860ea39a"
        ),
        tag: &hex!("10cf4d335b8d8e7e8bbaf49222a1cd66"),
    },
    TestVector {
        key: &hex!("a50a60e568ff35a610ef9479c08bbc7bb64c373fc853f37fa6b350250a26f232"),
        nonce: &hex!("5ada1d4aca883d7bd6fa869f"),
        plaintext: &hex!(
            "9ea44e72a1d21395cd81d20db05816441010efd8f811b75bb143ab47f55eefce4eec5f606fa5d98b260d7e5df4a7474cbd8599"
        ),
        aad: &hex!("cc7a7a541be7a6d1b846354cb6a571e6"),
        ciphertext: &hex!(
            "4165b135187faeb395d4531c062738e0d47df8bed91982eb32e391a6b3711f117b6fae0afde791de3e72fcf96d2b53ff1a621a"
        ),
        tag: &hex!("e2cbfea2100585b2cbe5107da17ff77a"),
    },
    TestVector {
        key: &hex!("5ff3311461d247ceb1eaf591292fcba54308dd3484fd1851e09a12b8f6663fc1"),
        nonce: &hex!("61af2e6aec183129cf053c2b"),
        plaintext: &hex!(
            "920df8b2888a74022ede6919ed0bf48ccf51e395fe5bfa69a6209ff9a46674024eaa4f43ae2c933730b9fdc8ad216130447cc8"
        ),
        aad: &hex!("5eafed6674f2ae83397df923e059db49"),
        ciphertext: &hex!(
            "0e35e1208168b639e012df398bc8bf2b19b08d46af0353cd78f6d1b7ae14e6224c1da6fdc9433b171f1cd2b512d5f1acd84f03"
        ),
        tag: &hex!("5bc77eb02e4d51e2019446b468498d0e"),
    },
    TestVector {
        key: &hex!("42e93547eee7e18ec9620dd3dc0e2b1cf3e5d448198a902ded3f935da9d35b33"),
        nonce: &hex!("e02e12ba92a6046af11adf0e"),
        plaintext: &hex!(
            "6c3704b32527ace3d5236687c4a98a1ad5a4f83c04af2f62c9e87e7f3d0469327919d810bb6c44fd3c9b146852583a44ed2f3c"
        ),
        aad: &hex!("ac3d536981e3cabc81211646e14f2f92"),
        ciphertext: &hex!(
            "8b6506af703ae3158eb61e2f9c2b63de403b2ebc6b1e6759ceb99c08aa66cb07d1d913ac4acd7af9b9e03b3af602bcaf2bb65e"
        ),
        tag: &hex!("a6ce2ccb236fc99e87b76cc412a79031"),
    },
    TestVector {
        key: &hex!("24501ad384e473963d476edcfe08205237acfd49b5b8f33857f8114e863fec7f"),
        nonce: &hex!("9ff18563b978ec281b3f2794"),
        plaintext: &hex!(
            "27f348f9cdc0c5bd5e66b1ccb63ad920ff2219d14e8d631b3872265cf117ee86757accb158bd9abb3868fdc0d0b074b5f01b2c"
        ),
        aad: &hex!("adb5ec720ccf9898500028bf34afccbcaca126ef"),
        ciphertext: &hex!(
            "eb7cb754c824e8d96f7c6d9b76c7d26fb874ffbf1d65c6f64a698d839b0b06145dae82057ad55994cf59ad7f67c0fa5e85fab8"
        ),
        tag: &hex!("bc95c532fecc594c36d1550286a7a3f0"),
    },
    TestVector {
        key: &hex!("fb43f5ab4a1738a30c1e053d484a94254125d55dccee1ad67c368bc1a985d235"),
        nonce: &hex!("9fbb5f8252db0bca21f1c230"),
        plaintext: &hex!(
            "34b797bb82250e23c5e796db2c37e488b3b99d1b981cea5e5b0c61a0b39adb6bd6ef1f50722e2e4f81115cfcf53f842e2a6c08"
        ),
        aad: &hex!("98f8ae1735c39f732e2cbee1156dabeb854ec7a2"),
        ciphertext: &hex!(
            "871cd53d95a8b806bd4821e6c4456204d27fd704ba3d07ce25872dc604ea5c5ea13322186b7489db4fa060c1fd4159692612c8"
        ),
        tag: &hex!("07b48e4a32fac47e115d7ac7445d8330"),
    },
    TestVector {
        key: &hex!("9f953b9f2f3bb4103a4b34d8ca2ec3720df7fedf8c69cac900bd75338beababe"),
        nonce: &hex!("eb731ae04e39f3eb88cc77fa"),
        plaintext: &hex!(
            "3b80d5ac12ba9dad9d9ff30a73732674e11c9edf9bb057fd1c6adc97cf6c5fa3ee8690ad4c51b10b3bd5da9a28e6275cbe28cb"
        ),
        aad: &hex!("d44a07d869ac0d89b15262a1e8e1aa74f09bcb82"),
        ciphertext: &hex!(
            "1533ce8e2fc6ab485aef6fcfb08ded83ae549a7111fce2a1d8a3f691f35182ce46fce6204d7dafb8d3206c4e4b645bc3f5afd1"
        ),
        tag: &hex!("f09265c21f90ef79b309a93db73d9290"),
    },
    TestVector {
        key: &hex!("2426e2d1cd9545ec2fb7ab9137ad852734333925bfc5674763d6ee906e81c091"),
        nonce: &hex!("49a094a71d393b36daa4a591"),
        plaintext: &hex!(
            "7cbe7982d365a55d147c954583f9760a09948ab73ebbe1b2c1d69ed58e092a347392192cfe8bce18ca43ee19af7652331bd92c"
        ),
        aad: &hex!("177309cfc913e3f5c093e8b1319ba81826d43ce5"),
        ciphertext: &hex!(
            "cab992e17cf6ec69fd3c67ea0424bcd67475a7f1f16e6733c4419d1b5a755f78d6eda8e368360d403800a08f0d52b4bc0aa0ab"
        ),
        tag: &hex!("b125f8caee9e54b9f9414b1c09021ed8"),
    },
    TestVector {
        key: &hex!("8dc1b24bcbbee3cb8e14b344166d461d00c7490041edc9fa07e19cc82a3ed9c4"),
        nonce: &hex!("31768ad18c971b188d947019"),
        plaintext: &hex!(
            "84e4f79dbb7209cbaf70e4fefe137c494786c899602783e9c034296978d7f0c571f7ea9d80ed0cc4723124872d7326890300c1"
        ),
        aad: &hex!("eb3673b64560cca7bda76a1de7ae1014ee1acaee"),
        ciphertext: &hex!(
            "2402acd865d4b731bc9395eae0e57d38fdf5ce847ac7aef75791a52c7573ea9b3a296e62cb1ed97c4bd34be50ee7f3d75747cf"
        ),
        tag: &hex!("665abb725498ede2b0df655fc1765a2b"),
    },
    TestVector {
        key: &hex!("bc898f643a5f2cd864c10b507b4b803b4ff4ace61fadcc7bcd98af394731b791"),
        nonce: &hex!("cc447d83c0a6734a79778c64"),
        plaintext: &hex!(
            "124eb963cdb56fa49c70a9b1aa682445c55065f26859f1d16eef7cfe491587533eedd7e23deabddfc5550c2fa6a08b17822699"
        ),
        aad: &hex!("e932bd2e0e6c550d136f725e14c53d27ffb20f6a"),
        ciphertext: &hex!(
            "45d8908ef9eef369e78b7ea0b7d023a92c63648271927efe9b0220eb09ed96f3b635c6ec8bfc68b4c228b712494bb37f4c7f1a"
        ),
        tag: &hex!("47899857494bac28d2176a9c923026b2"),
    },
    TestVector {
        key: &hex!("8e82a85466ee024eb1ae10c4982d6a95e6dbe5582299ab37fe89a9db80ab51a6"),
        nonce: &hex!("04cfd489e18eeb7a4a8ab36b"),
        plaintext: &hex!(
            "3aa2e4eaed18c4602715ae77379e9083708af9f9b49031324d41abca61440319c8c8e6dbcc20006a825b12ced00b2286848a94"
        ),
        aad: &hex!("7bb54b1a6ed0ca387268a146430c0bfa2602a8fd"),
        ciphertext: &hex!(
            "674b1391937074642408eeae9b748ca629da9fd00281824f5a108f6078ee78f98749392bb6e29b53e53e4b11739ac53a8e653b"
        ),
        tag: &hex!("e320a873a9c2e8ef455698c37ea59a6d"),
    },
    TestVector {
        key: &hex!("f1f2c5503ebf35ac1373c29e2305e963f89f6ed015a181b70fb549429805d5d9"),
        nonce: &hex!("2fb5c6a24f406872755db05c"),
        plaintext: &hex!(
            "b4a2809198035c277637bb1c2927fb5c60b49ef9087c800012d8663d997983fcb78d51a054114a24e1e1b5214b58e7dee47195"
        ),
        aad: &hex!("92c1f3489aed90aedafb55562a34b3f4be29e101"),
        ciphertext: &hex!(
            "f051a3a968278a46630b2894a0d386c18fa034960d8ddd14e88e1071afbbca5baf02967c2270117b4fb2bd4cfd032174505f99"
        ),
        tag: &hex!("6f1db5293660b6904f7f008e409bdc06"),
    },
    TestVector {
        key: &hex!("f0338d26d74bd1768da5bb79c59fab2b4abe1966324048790c44bc98a6b34b6c"),
        nonce: &hex!("c8269e4406fa0be1cf057b2f"),
        plaintext: &hex!(
            "323c373e4d85a1fd21f387fdd8c7e6aeebd5aae893d7af286cb214600cba8b9eb06df085a2dc5aed870259f7f3cc81d3eb53bd"
        ),
        aad: &hex!("13fb0edcba095cef9c4343a0629fd5020f03729d"),
        ciphertext: &hex!(
            "08572b9cf9bcfd21d4403a1218d94476b9ee8c3b94c56625c21ccaf4c0efa34cf22a532389210793699c9de1ab14f8c4c52928"
        ),
        tag: &hex!("29968c9fb610940cee9fd5b2f7c8ba21"),
    },
    TestVector {
        key: &hex!("a67648285b65b9196060aaa02af279170164353e38fb77c3968c403cfa9acdc8"),
        nonce: &hex!("0822d6b3e91eccb7e14245fd"),
        plaintext: &hex!(
            "b5d271768c12ccabf89eb2d58cbde840c26d1c9b3692581f90c8b0d7b2cff31ae9192d284f5448de7d924a7b08f115edae75aa"
        ),
        aad: &hex!("0d9a5af7ac27438d92534d97ff4378274790e59f"),
        ciphertext: &hex!(
            "b59041eed7abc2ff507d1932b5c55ac52728e5ac6648dcc74b38870db6181b1989f95a0144f0db368ec50414cfda0b977141e3"
        ),
        tag: &hex!("1d12ce89e1261d73470f3ae36ab87288"),
    },
    TestVector {
        key: &hex!("51162b2435f3cf43471f4cc0ffac98b438501ee9b887843a66e9951ca35b8767"),
        nonce: &hex!("dcb902eaa837ed22bf5fa636"),
        plaintext: &hex!(
            "3edf43358f5109a4dfb4a02987170a67cdd170f6028f7708bdd7726f476b882b9640270f2270f7babfa384181c8e58c15d04c4"
        ),
        aad: &hex!("4d459905ff89aed07dcda43a3d191a3da9309faa"),
        ciphertext: &hex!(
            "046a2313d36cbc43b6d0787e5ef37d153090a31d0f6656004034be72b9b07ace3a8abe8614362282d87da40c29c60a1a9f5c40"
        ),
        tag: &hex!("c7410b5cb94d2877c189983791cee82e"),
    },
    TestVector {
        key: &hex!("2fa2beb1cde2226f28fb42a5fb0af3fc58fbb76bf14aa436e6535d466456a0f4"),
        nonce: &hex!("50190514a3740b3c0b1df576"),
        plaintext: &hex!(
            "a5e0b4837dfca263ba286abf7940b6e70fabb55d8dee5028617c1190fbd327f79b79d2f34db6076ab07cecff7114b15ca02a33"
        ),
        aad: &hex!("25142928c1ae9c7b850309e07df359389db539fc"),
        ciphertext: &hex!(
            "850fd22bd0897b98ce40bc6c1345a9d59abf796b1b8c34ee8b377e54ee7d59dec05c022ecae96ffdfa1311bdd4e7a9d35aac47"
        ),
        tag: &hex!("4b5ab89b4f627ca32d12a1791c286870"),
    },
    TestVector {
        key: &hex!("a92a797ce2b2f382030b77a1abe94c8076eee88de2dc4929350b244dbdaddd30"),
        nonce: &hex!("716f577401a7893c42c91710"),
        plaintext: &hex!(
            "9d26ff79a89720fab6e4cda85887e3c0c3f86a4670d065c8ea68042b6f9f16dd2c5b31acb36331f5b1e50f08c492dc12eebd9e"
        ),
        aad: &hex!("8642681f1839b88990c2a939f00c9b90766dadac"),
        ciphertext: &hex!(
            "3080bcf3604cf81f5f2c6edc80dfe5d877168a9903598a700a0bbae188fadc7a8b76a04b40400f9252d7f9437fa8f024a3bdeb"
        ),
        tag: &hex!("8fc56f6bf48efb00476886b2a03ecb89"),
    },
    TestVector {
        key: &hex!("89d0723e5a087456b7b709b8b21be380b463ba3dc9b79170e9947526798fe91c"),
        nonce: &hex!("68e2f307b7d49d4d9c041755"),
        plaintext: &hex!(
            "7fe2afb710e8fd49cca1c2ba8fd0814594fba4d667017630e170a8a379fa5837bf370ca1cd4c98bd8c4f13eb7068ffa71ab07c"
        ),
        aad: &hex!("b34805b30703a62b6d37c93f2443e1a33154b5fb"),
        ciphertext: &hex!(
            "b841012752bbf1dfa7b59366dbf353bf98b61ff2e6e7a13d64d9dcb58b771003c8842ac002aac1fa8ca00a21eaf101ab44f380"
        ),
        tag: &hex!("73a93e2722db63c2bbf470d5193b2230"),
    },
    TestVector {
        key: &hex!("329a6e94b1cce693e445694650d62b8c2c9ab03a09e6d4eca05c48291e576b89"),
        nonce: &hex!("78f471bc32f8637a213e87ac"),
        plaintext: &hex!(
            "65264d75e1a176a7e966e59109cd074ac5d54740eb0c58084af023e5599eb611846199579d95ba94b6d25ee4d9074b9714f231"
        ),
        aad: &hex!("c00c465524e2e2f8a55c0793ed9af851be45a70e"),
        ciphertext: &hex!(
            "964d665d1e3c1018dfd883e217cfe4c856cc844f7644b53bb68fbe66f8541fa43ac54e92a2b194d6d8929fe031e94b3e70eca0"
        ),
        tag: &hex!("fd511385711236f2e99e6da5042007b7"),
    },
    TestVector {
        key: &hex!("463b412911767d57a0b33969e674ffe7845d313b88c6fe312f3d724be68e1fca"),
        nonce: &hex!("611ce6f9a6880750de7da6cb"),
        plaintext: &hex!(
            "e7d1dcf668e2876861940e012fe52a98dacbd78ab63c08842cc9801ea581682ad54af0c34d0d7f6f59e8ee0bf4900e0fd85042"
        ),
        aad: &hex!(
            "0a682fbc6192e1b47a5e0868787ffdafe5a50cead3575849990cdd2ea9b3597749403efb4a56684f0c6bde352d4aeec5"
        ),
        ciphertext: &hex!(
            "8886e196010cb3849d9c1a182abe1eeab0a5f3ca423c3669a4a8703c0f146e8e956fb122e0d721b869d2b6fcd4216d7d4d3758"
        ),
        tag: &hex!("2469cecd70fd98fec9264f71df1aee9a"),
    },
    TestVector {
        key: &hex!("55f9171a03c21e09e3a5fd771e56bffb775ebb190319f3dc214c4b19f72e5482"),
        nonce: &hex!("14f3bf95a08e8f52eb46fbf9"),
        plaintext: &hex!(
            "af6b17fd67bc1173b063fc6f0941483cee9cbbbbed3a4dcff55a74b0c9535b977efa640e5b1a30faa859fd3daa8dd780cc94a0"
        ),
        aad: &hex!(
            "bac1ddefd111d471e75f0efb0f8127b4da923ecc788a5c91e3e2f65e2943e4caf42f54896604af19ed0b4d8697d45ab9"
        ),
        ciphertext: &hex!(
            "3ae8678089522371fe4bd4da99ffd83a32988e0728aa3a4970ded1fe73bc30c2eb1fe24c0ff5ab549ac7e567d7036628fd718d"
        ),
        tag: &hex!("cf59603e05f4ed1d2da04e19399b8512"),
    },
    TestVector {
        key: &hex!("54601d1538e5f04dc3fe95e483e40dec0aaa58375dc868da167c9a599ed345d9"),
        nonce: &hex!("c5150872e45c341c2b99c69a"),
        plaintext: &hex!(
            "ae87c08c7610a125e7aa6f93fac0f80472530b2ce4d7194f5f4cb8ac025323c6c43a806788ef50c5028764ec32f2839005c813"
        ),
        aad: &hex!(
            "93cd7ee8648a64c59d54cdac455b05ffdfc2effe8b19b50babd8c1a8c21f5dc8dc6050e2347f4cd28701594b9f8d4de5"
        ),
        ciphertext: &hex!(
            "d5f005dc67bdc9738407ce2401977f59c9c83520e262d0c8db7fe47ae0eada30d674694f008e222f9733a6e63d81499e247567"
        ),
        tag: &hex!("3470155144c74929980134db6995dd88"),
    },
    TestVector {
        key: &hex!("e966c470cbecc819260640d5404c84382e6e649da96d29cad2d4412e671ed802"),
        nonce: &hex!("b3a92d6f49fe2cb9c144d339"),
        plaintext: &hex!(
            "7adf6fcb41d59b8d2b663010c3d4cf5f5f0b95cf754f76f8626c4428467e5c6684e77e7857b1cc755762e9ea9117e3bb077040"
        ),
        aad: &hex!(
            "dfa62a3a4b5b3af6770cfd3cef3bbb4cce3f64925782a9a8a6e15fe3744d8f9310400dd04e8d7966c03850539e440aa5"
        ),
        ciphertext: &hex!(
            "5f5b09486e6cd2a854e5622b4988e2408fddaca42c21d946c5cd789fe5a1306ef33c8cd44467ad7aa4c8152bce656a20367284"
        ),
        tag: &hex!("2b388109afdada6473435230d747b4eb"),
    },
    TestVector {
        key: &hex!("4a8a12c0575ec65ae1c5784d2829bc7b04818eb00bd4c90a0d032ea281076e27"),
        nonce: &hex!("959f113b705397fb738018b0"),
        plaintext: &hex!(
            "0c5571195586e4fc7096fb86cfcd6684081446f3d7adc33a897f03ac4ff6c3cc2019b67bd3184c86070764f6deaa8a10d0d81f"
        ),
        aad: &hex!(
            "adb8bc96142a1025122dc22f826957197af33dcdcf6b7ab56bc1a5e17e8534e48b8daf685faf9543bb343614bdf6737f"
        ),
        ciphertext: &hex!(
            "84212d5991231d35c4e8621163e5b370a0105a05856866e74df72c0808c062981570d32d274ea732fa4d29f9cfa7839cadbe6a"
        ),
        tag: &hex!("39cee3b8fa0bf92605666ccd9eb19840"),
    },
    TestVector {
        key: &hex!("6197a4fa7cfcedeff223f69ea68b4ddf54b683350c20875be353077e9bbce346"),
        nonce: &hex!("1a69ecabd42c53c0ec64fcd0"),
        plaintext: &hex!(
            "40a487b4daf866c20f3c4911a0586709c3344aa988dc9c464bcf36cc4e3d92701e611e60cf69f3edbf76cd27ff6ba935026d7f"
        ),
        aad: &hex!(
            "b20a7ca5b5b603f661587e01f7ef171823ef463c187ded77a3d616400cc1d2b0b688ac9e927498341560cbc8eb9a4198"
        ),
        ciphertext: &hex!(
            "06420fa038ee62db30cc05bfe34c8d2c39a9d439653907c512ed606511921fe76110913a5bfb6b6c7b23d7f8883f5ab65f4b14"
        ),
        tag: &hex!("4d3097c9919002cd1da83f29820312ed"),
    },
    TestVector {
        key: &hex!("c9dbe185023ecaa78be9bfac1b91b9da6bd7c11349feb69e6b0be83a838e77b2"),
        nonce: &hex!("8940fa7c6afd3f7a09ec93b6"),
        plaintext: &hex!(
            "075be0d61273e6975978d0b88b3fa38fc398d4d0f22a342a8afa5562af0e7c8fa548f0d8faec898a20c97e851754992c1ed4a3"
        ),
        aad: &hex!(
            "f17bd357608365e66b98e49191cdc2a3813bba5a1b7988aa8aaaaad4b86d0ef4e2698cad799d63fcd2a5e87c0e3e929a"
        ),
        ciphertext: &hex!(
            "615c1097d577363a77bfc7dd57179acb68166e78021b3397d7029ce33cbc848f036b9c07989eeb9f42aeaeebe8542f103b1d32"
        ),
        tag: &hex!("a22ab25fd8a6127469e8ce9ff686d575"),
    },
    TestVector {
        key: &hex!("e6cdcf497a6e119009bf43ac183d2dd4d4e967964ef92811f69eb18d92923305"),
        nonce: &hex!("3e88459a76e1dcc890788297"),
        plaintext: &hex!(
            "72a3dfb555ba0029fc3d1c85b836f76135bd1858189efdde2db29045f2c26e6a65627d81a0b85ca42e8269d432a41154e929ac"
        ),
        aad: &hex!(
            "a359f86ec918537d80a84da7b66bca700c1ff9ec7f8695a30808d484da218d15ae89c5f943e71778445130191f779001"
        ),
        ciphertext: &hex!(
            "9ae3f8ccae0bb5789b1105118760c406e41175a76612435cb0c8be225ea6b368c9d08c9d9a24b512d1458e94af79e3060ab69e"
        ),
        tag: &hex!("ac3bbc8fd6a7097df6f298411c23e385"),
    },
    TestVector {
        key: &hex!("de5531b50888b61d63af2210ee23f46d91a5e60312bd578584af586bf22ea756"),
        nonce: &hex!("0fde8689b0348bbcfaa89fec"),
        plaintext: &hex!(
            "80621e54eef1c92afb1f64ed860e39311eea7e2cca6f5624008c1d2e581d7112b7ee0b559fc3db575b7b7c42ee4f2a20442dc0"
        ),
        aad: &hex!(
            "22db97cd5f359f12aec66c51c7da79ba629db4c8c7e5501be2ec1e4cc3f3944b6e3057d093bc68b735b5156950f91804"
        ),
        ciphertext: &hex!(
            "933018419a32b7bf65f9777c44889a44b32d61ceddbb46839366ce2ca2ffeb1833f46559e59c93bb07f622d9633f13932cf7f1"
        ),
        tag: &hex!("25023a4ee9bdbf525cfef888e2480f86"),
    },
    TestVector {
        key: &hex!("bc0c6368a9bb2622f6d5ba12de581f003336c298adac34499bf26b11e630f891"),
        nonce: &hex!("2aa8f30b567cf1edd818e42d"),
        plaintext: &hex!(
            "1dcc1a3167fba55c00d3383e26d386eaa0449154599992da7f7f6598f41b3eb8e4d0a9143dfcab963f5c390a6ae2010fbcf6ec"
        ),
        aad: &hex!(
            "0e28ebf87eb757e83031fb836f7b049a46bd740b0a39c9b798d2407e1150da86dfe84121c7c98449559453ad7558e779"
        ),
        ciphertext: &hex!(
            "78d00a6e3302369817b9cf1f24ea13c41751382e3fea74403d094737e32fb507184cfebce48d10b4ce8db12ef961e4df2c8e95"
        ),
        tag: &hex!("c0aff3594f86b58e229c7ad05c2b84f0"),
    },
    TestVector {
        key: &hex!("5d98a0c7ad6f9c0b116613ca5082250356a6a9bca55fe1a4a2962b733214dac4"),
        nonce: &hex!("8b2d8e8d83bdd6a3125dd997"),
        plaintext: &hex!(
            "4f3685c2cfbc856379d1fd00f9611fe4c0a4b9c4013fe1bee144449709a6a7e31ff6fb0da74ed464b066b03b50f19cd7f5f9bc"
        ),
        aad: &hex!(
            "2f20636d46ce37e9bb0ca0c41d819e3eabcedacbd1ca3ced112d3ad620bbd3b2effe80d3ec8760706e8f14db83139a70"
        ),
        ciphertext: &hex!(
            "8e178c0e3e5d22b3be897e0b8879b0d53fef2efb9946ccff6d717b001e3033f2cc22d01d9551e9c0749de704fbe3189328cbb0"
        ),
        tag: &hex!("541b7db823e37b5ed323626b9c6748f6"),
    },
    TestVector {
        key: &hex!("d80a2703e982de1a2fe706ffe6e389f351ab356ccf056df045e2941b42ef21a4"),
        nonce: &hex!("1521ab8f7242cba05427f429"),
        plaintext: &hex!(
            "6f9fde28e85776a49cfbad1459d94611757a3cd996aa6e2d702d0483a4d88d532131ebd405b351226b16d19d30d32807a1d511"
        ),
        aad: &hex!(
            "5395de90d6bec7c159ab9d6cfa663bdc6295d025e1fcc8b760b9ba42d785eda218dabc6fa7c0f733ad77f61682bff2db"
        ),
        ciphertext: &hex!(
            "1e72a8495ceadaf0d31b28ba7cb7c37ccb117761d38fe7dd98eb230ff4ea0b400401e9b5311a7be9b2a533523ad469e2fdb233"
        ),
        tag: &hex!("bb174b7624c935ff75b3b77ff7068a98"),
    },
    TestVector {
        key: &hex!("6d5c69d7135c0b5b7fef512c127fa788092f1a908358ab658b8f23e463409aa5"),
        nonce: &hex!("b36cccad38cd6148a384a026"),
        plaintext: &hex!(
            "b4e74f5c56f2ea056d9ff931525944dfad207e063ba226c354e0320a50449967e964580d9b57028c14005aba6865f8bc6a3ef8"
        ),
        aad: &hex!(
            "b19f4616bb1452251a2a7dbf78f920194f139e0424d27683621d1ee1e865737c2466e058439c8e122e582a7b63607ce9"
        ),
        ciphertext: &hex!(
            "1ce12cd5502efa9ea259584ae9b3c7dbd9444380d4b77a2c787f9b2257019b23ee183dffebb3106a26b18d8a23445626a578e2"
        ),
        tag: &hex!("62945e31bae3181855b69c37898ac5bf"),
    },
    TestVector {
        key: &hex!("e6afe3c4db2c1d13edb1c5931b2b4b515ec0fd6201139ee1ea55cec92263830e"),
        nonce: &hex!("358bd9ea64177d1e23a41726"),
        plaintext: &hex!(
            "710bb3394b094ee7d053bc6599b26dafd337e8a61c580d0446c3bf195e77ca5132c8ec3a47a61579dce38360bba7c65e4d5634"
        ),
        aad: &hex!(
            "7e0f841cddd7eeebd1ec7b7b8d0e2f71656e5e9ff3cfa739c0b9d0ec4941a0b3f3b396690dbe5f5082d6fb6dd701c68d"
        ),
        ciphertext: &hex!(
            "4574a8db515b41c14c2a962dff34e2161a7195c491b11b79889aff93c5b79a6455df9fe8ef5c5b9edb5da1aa9fe66058b9065f"
        ),
        tag: &hex!("7c928d7f5cbac9bb4b5928fe727899eb"),
    },
    TestVector {
        key: &hex!("5cb962278d79417b7795499e8b92befe4228f3ba5f31992201aa356a6d139a67"),
        nonce: &hex!("76f7e7608f09a05f336994cf"),
        plaintext: &hex!(
            "2e12cbd468086aa70e2ecd1ddef561e85c225dd083e5956f5c67503344b0ea982bb5044dafbcc02a5b9be1e9b988902d80172b"
        ),
        aad: &hex!(
            "032de3fdec273fc8446c2bf767e201f2c7c190acf9d6d321a24a0462cbc3356e798fe23d6c1b4fe83be9c95d71c05504"
        ),
        ciphertext: &hex!(
            "c959344a46aa5216d2b37c832436eb72a4a363a6df5642cfbbfd640dea1d64c80bd97eabc1aab192969ee0b799e592a13d2351"
        ),
        tag: &hex!("51b227eaf7228a4419f2f3b79b53463a"),
    },
    TestVector {
        key: &hex!("148579a3cbca86d5520d66c0ec71ca5f7e41ba78e56dc6eebd566fed547fe691"),
        nonce: &hex!("b08a5ea1927499c6ecbfd4e0"),
        plaintext: &hex!(
            "9d0b15fdf1bd595f91f8b3abc0f7dec927dfd4799935a1795d9ce00c9b879434420fe42c275a7cd7b39d638fb81ca52b49dc41"
        ),
        aad: &hex!(
            "e4f963f015ffbb99ee3349bbaf7e8e8e6c2a71c230a48f9d59860a29091d2747e01a5ca572347e247d25f56ba7ae8e05cde2be3c97931292c02370208ecd097ef692687fecf2f419d3200162a6480a57dad408a0dfeb492e2c5d"
        ),
        ciphertext: &hex!(
            "2097e372950a5e9383c675e89eea1c314f999159f5611344b298cda45e62843716f215f82ee663919c64002a5c198d7878fd3f"
        ),
        tag: &hex!("adbecdb0d5c2224d804d2886ff9a5760"),
    },
    TestVector {
        key: &hex!("e49af19182faef0ebeeba9f2d3be044e77b1212358366e4ef59e008aebcd9788"),
        nonce: &hex!("e7f37d79a6a487a5a703edbb"),
        plaintext: &hex!(
            "461cd0caf7427a3d44408d825ed719237272ecd503b9094d1f62c97d63ed83a0b50bdc804ffdd7991da7a5b6dcf48d4bcd2cbc"
        ),
        aad: &hex!(
            "19a9a1cfc647346781bef51ed9070d05f99a0e0192a223c5cd2522dbdf97d9739dd39fb178ade3339e68774b058aa03e9a20a9a205bc05f32381df4d63396ef691fefd5a71b49a2ad82d5ea428778ca47ee1398792762413cff4"
        ),
        ciphertext: &hex!(
            "32ca3588e3e56eb4c8301b009d8b84b8a900b2b88ca3c21944205e9dd7311757b51394ae90d8bb3807b471677614f4198af909"
        ),
        tag: &hex!("3e403d035c71d88f1be1a256c89ba6ad"),
    },
    TestVector {
        key: &hex!("c277df045d0a1a3956958f271055c229d2634427b1d73e99d54920da69f72e01"),
        nonce: &hex!("79e24f84bc77a21a6cb14ee2"),
        plaintext: &hex!(
            "5ca68d858cc30b1cb0514c4e9de98e1a1a835df401f69e9ec6f1bcb1158f09114dff551683b3827457f77e17a7097b1ea69eac"
        ),
        aad: &hex!(
            "ca09282238d492029afbd30ea9b4aa9d448d77b4b41a791c35ebe3f8e5034ac71210117a843fae647cea020712c27e5c8f85acf933d5e28430c7770862d8dbb197cbbcfe49dd63f6aa05fbd13e32c459342698dfee5935c7c321"
        ),
        ciphertext: &hex!(
            "5c5223c8eda59a8dc28b08e6c21482a46e5d84d32c7050bf144fc57f4e8094de133198da7b4b8398b167204aff837da15d9ab2"
        ),
        tag: &hex!("378885950a4491bee3cd681d3c957b9a"),
    },
    TestVector {
        key: &hex!("4d07f78d19e6d8bb32bf209f138307890f0f1ae39362779ff2bf1f9b734fe653"),
        nonce: &hex!("d983a5d5af78a3b1cd5fbd58"),
        plaintext: &hex!(
            "94f0bbc4340d97d854e25cc7ce85ea1e781e68bf6f639e0a981bb03e3c209cbf5127171cb0fff65bc3ecac92774d10146d1ac5"
        ),
        aad: &hex!(
            "a3dc9ff9210bc4b3276909883db2c2aa0762cd22b46901a248c0372d073e7778b9c1d8469b26bb42406e484ef7747f71dea785fc0020a2eac17e0ac3fbe0453629efd68d5678fbecc10af8ffbe7828f826defb638763f4ecfe82"
        ),
        ciphertext: &hex!(
            "6543b4d97fccd273b36436fef719ac31bf0e5c4c058ea71aea2a0e5b60e329be6ea81ce386e6e9fe4480e58363c3b2036865ac"
        ),
        tag: &hex!("924cf7c0770f228a4b92e9b2a11fc70b"),
    },
    TestVector {
        key: &hex!("9572b9c57abdf1caae3bebc0e4bbf9e556b5cbacca2c4756050fefd10a666155"),
        nonce: &hex!("de292a9858caaccdcab6a433"),
        plaintext: &hex!(
            "6f420a32708ccd4df0d3149e8c1d88dceba66ee4546f38db07046ebf30f47627f7fdda1dd79783adabe5f6b6853857b99b864c"
        ),
        aad: &hex!(
            "a042d97a9b8f6caf51c5f24522d7ed83e2c5d8ec6b37ef2598134a30e57319300c3fdf92fb1d9797f5ef00971f662aae768f69f9ca0455bd6d1059d5f85b8ecb977006b833f90ac2d5bbf4498c83f4d1a42584c0dfc4a2e2453c"
        ),
        ciphertext: &hex!(
            "a9af961d61ab578cc1348eb6f729603f481c5d9bf9bee3a13eda022bd09c03a4f207c21c45c0232a9742ae8f0c54b4278a3a63"
        ),
        tag: &hex!("eff9bb26156ec76f0060cd93a959e055"),
    },
    TestVector {
        key: &hex!("3cc8671c4d25c3cbc887f4dcbd64e531e91cf6252f6ee9c29d9988d20ab6747f"),
        nonce: &hex!("f960a09c0b5067280926a9c3"),
        plaintext: &hex!(
            "5b58717b0b32076566b58bf37c6133e61468b2be67715fb0007fe390c4b5578decf55502a4e3c12e7bdf0ba98784d126e4753a"
        ),
        aad: &hex!(
            "79d73a7ff86698e6114a0f465373fbee029e042424c439b22e3ad37b36b9e02bab82e16844114e99e39c169f462fe61b87c4627c394384acc9531680706e4e56491a304c6075cca37c64db24468c1fb9519605c83f0ee3e0316a"
        ),
        ciphertext: &hex!(
            "1d0be097470c1ac30619f63c3961152ab27db88ce694b7bba4db185cb31803cc7bab890e931c90766621bfe5d887eb0cd6995d"
        ),
        tag: &hex!("dbd57ea091ff16fc7dbc5435030cc74e"),
    },
    TestVector {
        key: &hex!("882068be4552d7ad224fc8fa2af00d6abf76ccf1a7689d75f6f0e9bd82c1215e"),
        nonce: &hex!("890a5315992f12674d1c8018"),
        plaintext: &hex!(
            "8464c03e0280cb1f63c054a24a050e980f60cc7313f09f2092c45d77bbe9ad2a8c1f6cdca2acd8c57c87e887edadb66bcb66c4"
        ),
        aad: &hex!(
            "916721df816b1cad531dee8e4a8e634d43ed87db99609bcc986d16bfac2cff577d536d749a5c3625de53c5351825c228911f0a64be1fc9738a26394efe5332c0762bf59b65d3f1c5aafa9ca2e63eccd59568e6c0269950911a71"
        ),
        ciphertext: &hex!(
            "020e297d907177dba12dde4bfe1b0ff9b6a9d9db0695193e4181449e157137b59b488616ba151b06d889f8498ce373d2396ab9"
        ),
        tag: &hex!("e48537ecb27460b477a6e7c3463dbcb0"),
    },
    TestVector {
        key: &hex!("4deadcf0f7e19231f8afcb6fb902b105bef23f2fa9323a51833ff8368ccb4f91"),
        nonce: &hex!("6d4d01abd587ed110e512ed2"),
        plaintext: &hex!(
            "75686e0fdd3fd96f3e6dfafd7a2a907f9f375d93943cb2229bd72b032bf624af4fc72071289386e3dccc45959e47ab42b261a2"
        ),
        aad: &hex!(
            "31a2797318104b2dc9977e599435b041c56bafe5e7d901a58614c2d3fb9d220e3fd3e2828cef69e0604ed73340cb1e21967294dcd874893942442200b2a5b860ee8cf91e1d8eb3d364d0e43e84f6379f434a1ae17c236b216842"
        ),
        ciphertext: &hex!(
            "8feaf9a089599812117a67aed2f4bf3431ff1f6cfd64ea5ff475287abb4ff1ab6b3e4f8a55d1c6b3f08594f403e771ec7e9956"
        ),
        tag: &hex!("5040407621712e053591179e1689698e"),
    },
    TestVector {
        key: &hex!("80f1c515f10d79cdbee275213aa9ac0845e2cf42874f7e695081cb103abf1a27"),
        nonce: &hex!("399d5f9b218b62ff60c267bd"),
        plaintext: &hex!(
            "9e95221873f65282dd1ec75494d2500e62a2b6edda5a6f33b3d4dd7516ef25cf4154472e61c6aed2749c5a7d86637052b00f54"
        ),
        aad: &hex!(
            "d2a8fff8ae24a6a5efc75764549a765222df317e323a798cbb8a23d1af8fdf8a3b767f55703b1c0feba3912d4234441978191262f1999c69caa4e9a3e0454c143af0022cd6e44cec14149f9e9964a1f2c5e5a6e3e768bd870060"
        ),
        ciphertext: &hex!(
            "4f996562e23ebbfd4fe26523aee9525b13d6e134e72d21bdc7f195c6403501fd8300b6e597b668f199f93591ba742a91b54454"
        ),
        tag: &hex!("2da1c7325f58575d275abf96c7fa9e51"),
    },
    TestVector {
        key: &hex!("c2c6e9be5a480a4a56bfcd0e268faa2276093bd1f7e8ce61e746d003decc761e"),
        nonce: &hex!("c1541eb25721d4856df8f928"),
        plaintext: &hex!(
            "87d22e0318fbbb420b86b0585bd12c14645ff2c742e5639b3a114cc96c5f738edfbe2055116f259e3d6c14cb6d8fca45708289"
        ),
        aad: &hex!(
            "f34e79e5fe437eda03ccfef2f1d6319df51a71c9891863e4b98a7298bd64490460354db5a28b0fadcb815024ea17f3b84810e27954afb1fdf44f0defb930b1793684a781310b9af95b4bcf0a727a2cb0ac529b805811b3721d98"
        ),
        ciphertext: &hex!(
            "b5d6e57c7aa0240e0b6e332d3b3323b525a3d8a553ad041ba599e909188da537c3293d1687fb967882d16a5615b84e95f9dd77"
        ),
        tag: &hex!("1cce334cec4b51216cac0fc620cdadf9"),
    },
    TestVector {
        key: &hex!("ea0d6184a71456e27f9ac82dfc7f6694c898f7c0d19d1cb0db4e575dd0094bb6"),
        nonce: &hex!("5018fb816d515511bfb939d5"),
        plaintext: &hex!(
            "083147d0c80f134f7393855c8a95bf6e6abd6f9a7b1fca584e8bfc6b5dc13a8edbfd473e232c041d9be9ee7709dc86b3aa320a"
        ),
        aad: &hex!(
            "8bc6bd0a263212bd7281fd1a45e512fca104f859358eae9293a297c529a0abaffd8a77507b9069040f2b3141a7620691e110a8b593b956d8e3e71694506b89018a03861c1ba6082687adce15a874c73477430cef075eba077a93"
        ),
        ciphertext: &hex!(
            "f0a5c4941782e2f2941dd05acee29b65341773f2e8d51935a3f4fa6f268ff030c880976cf1ee858f6571abd8411b695a2fadf0"
        ),
        tag: &hex!("067d8cc2d38c30697272daa00c7f70cf"),
    },
    TestVector {
        key: &hex!("c624feb6cb0d78d634b627134c692f0bf5debf84d8639e22ff27ce2ace49d438"),
        nonce: &hex!("a54f4f1204255f6b312222cd"),
        plaintext: &hex!(
            "ec34f45c1b70fd56518cc5c404cc13330ab7d51c10f4d2cfeb26b097ae76897191ec1b3953b0086e425c7da221d29f65d5ccf3"
        ),
        aad: &hex!(
            "d9099ba6be50dca77e0b9803766ad993132479fbab43b8f4126a7f9ef673ac0caf2de235e1e84ad9fe505c43d1ac779f5072c025c14ea0d930ce39db8c5930baada23b3e4654470e559fcb6eb1c133a77318b87cc7913e12d404"
        ),
        ciphertext: &hex!(
            "713d28a5123d65e82cca6e7fd919e1e5e3bdaab12ae715cf8b7c974eb5f62be8c3b42637074c6b891f6c6033eb4b7e61db9f0b"
        ),
        tag: &hex!("01ededff6e4d1dce4ac790218e208ebe"),
    },
    TestVector {
        key: &hex!("1afc68b32596198ae0f3a8612751c2413322e8054ff2ac6bede3d4a1ee20ee62"),
        nonce: &hex!("356860e76e794492de6a68f3"),
        plaintext: &hex!(
            "293041038f9e8edee23d2f18bce87b522380f1fa18b3021830a54ab891da8548095228ed9860176152e27945d66254f0db8590"
        ),
        aad: &hex!(
            "205e44009e0ef963838aff615b35c9f1271d487cf719677d956718bce8ab676cceb636ad381432c5c790c26b07051b661a2fec4e607f9644f84993c8335db21ae36b6008bab2883ad7541809bf5f49272295c1c1f1cf8c678553"
        ),
        ciphertext: &hex!(
            "e06109680d5fefd345665ec9a5b2e7bf3ece3af1b62841a95c453e7753b5a1d6d8a10b3c6c42df1f23832b74e74871821f1c0b"
        ),
        tag: &hex!("953d8d04f70e2af055ac902a455235b2"),
    },
    TestVector {
        key: &hex!("f61b723359e798fefecc26b10b168dc331c639079598f1f651166cc58c671ee1"),
        nonce: &hex!("b07e9407b592d4fd95509343"),
        plaintext: &hex!(
            "2724f1ad6b5b409a59c7f2ff649eb24b4a33a03d7a0426e29a6ea3aa91b4f00699fbed75bb7189964303e2e9fe3a7e5f74b7a1"
        ),
        aad: &hex!(
            "1429c6f27828cb94ad5e62451da10fd574660cec2b8f279a19bbb8a167a630d3ac60db04e8faa02204792e49aed4501844a419d3ecdff0d03799866fee81a91187b08a44d5bb617ff3b2cef79cd48750ea20903e1d3627a17730"
        ),
        ciphertext: &hex!(
            "362bad8de943dce8f53edf682d02e1d893c23c5272b13fd35b492f8477083a8c34027db32b6131931f03555ac5fbc6dbb13801"
        ),
        tag: &hex!("a51775606343755691f125019b44fdfc"),
    },
    TestVector {
        key: &hex!("6be7f4d18ff0fbdd9b3b3cacaba4629a0c617387079add62f6ce1584b33faad1"),
        nonce: &hex!("fda568c9cb13d9c176bcef03"),
        plaintext: &hex!(
            "4df668e99d5068604a48bcca5baa8245435928558a83d68d7b0b081861224e9bd39ea8f2d55a635949e66c6f6a7ff5cc34dd94"
        ),
        aad: &hex!(
            "11ebeb97dd4a9925c1fbe2b9af77392058d2d971e42db15da39f090d7bc132573c34bf7d92a2d72dc66ee6840c3ff07985b8976ee8d8f36bf47ae330b899fdc60652dd5a23c45f3680f11951f019e0697c8acfcaa95f01b9c7dd"
        ),
        ciphertext: &hex!(
            "488b40ad594e1845ccdd9e9467fc5e1afbbfde34e57d45bfcd30b61cc326d57fe8e3f31a39cdebf00f60bbd2c3cdf69f756eff"
        ),
        tag: &hex!("3bf3fbab9b48486fd08a5552604df639"),
    },
];

#[test]
fn test_nist_cavs_vectors() {
    for tv in TEST_VECTORS {
        // Full (all at once)
        let mut key = Key::default();
        key.copy_from_slice(tv.key);
        let mut nonce = Nonce::default();
        nonce.copy_from_slice(tv.nonce);
        let mut cipher = AesGcm256::new(&key, &nonce, tv.aad).unwrap();
        let mut buffer = tv.plaintext.to_vec();
        cipher.encrypt(&mut buffer);
        let tag = cipher.into_tag();
        assert_eq!(tag.len(), TAG_LENGTH);
        assert_eq!(tag.as_slice(), tv.tag);
        assert_eq!(buffer.as_slice(), tv.ciphertext);

        for size in &[
            1,              // Byte per byte, forcing unaligned
            BLOCK_SIZE + 1, // BLOCK_SIZE + 1, forcing unaligned with extra data
        ] {
            let mut cipher = AesGcm256::new(&key, &nonce, tv.aad).unwrap();
            let mut buffer = tv.plaintext.to_vec();
            let mut chunks = buffer.as_mut_slice().chunks_mut(*size);

            for chunk in &mut chunks {
                cipher.encrypt(chunk);
            }
            let tag = cipher.into_tag();
            assert_eq!(tag.len(), TAG_LENGTH);
            assert_eq!(tag.as_slice(), tv.tag);
            assert_eq!(buffer.as_slice(), tv.ciphertext);
        }

        // Unauthenticated decryption
        let mut cipher = AesGcm256::new(&key, &nonce, tv.aad).unwrap();
        let mut buffer = tv.ciphertext.to_vec();
        cipher.decrypt_unauthenticated(&mut buffer);
        assert_eq!(buffer.as_slice(), tv.plaintext);

        // Authenticated decryption
        let mut cipher = AesGcm256::new(&key, &nonce, tv.aad).unwrap();
        let mut buffer = tv.ciphertext.to_vec();
        let tag = cipher.decrypt(&mut buffer);
        assert_eq!(buffer.as_slice(), tv.plaintext);
        assert_eq!(&tag[..], tv.tag);
    }
}
