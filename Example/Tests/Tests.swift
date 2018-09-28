import XCTest
import TrezorCryptoEd25519WithBlake2b

class Tests: XCTestCase {
    
    public static let secretKeyLength = 32
    public static let publicKeyLength = 32
    public static let signatureLength = 64

    func testJS() {

        let message = "1234567890".hex2Bytes
        let publicKey = "efb88370952a27546dec4ec10a2e57d3d6503de6535cccfc6277f24af48b9ecb".hex2Bytes
        let signature = "76493b077cbbf74fec8e0523f6f88ec05550b04282e8e65ab4a73061689b4151699b5248a565f1892a05851463bbfb4ecae36923fa0a40974ff9e8e59a89e709".hex2Bytes
        let ret = ed25519_sign_open(message, Int(message.count), publicKey, signature) == 0
        XCTAssert(ret)
    }

    func testGo() {

        let message = "01020304".hex2Bytes
        let publicKey = "6de90010f79c9bb22f3cfa8e1a4e8689e0c2d5c43648d4fd7b665cac5344c035".hex2Bytes
        let signature = "49da47bc6dbcf1f1fd453a9e5122e6003619260671490c2ac7493513b4efb3afd4830d790a6363f6812005244bd5278828058bfde1cdc6c0e3481e9a27adff06".hex2Bytes
        let ret = ed25519_sign_open(message, Int(message.count), publicKey, signature) == 0
        XCTAssert(ret)
    }



    func testMore() {

        let messages = ["3132333435363738393054455354",
                        "3132333435363738393054455354",
                        "3132333435363738393054455354",
                        "3132333435363738393054455354",
                        "3132333435363738393054455354",
                        "3132333435363738393054455354",
                        "3132333435363738393054455354",
                        "3132333435363738393054455354",
                        "3132333435363738393054455354",
                        "3132333435363738393054455354"].map { $0.hex2Bytes }

        let secretKeys = ["afa2a3ab3347b5bbe210dc099b2e010e5491d698e5112db6bc278cfd8fa27eb9f0fde0110193147e7961e61eeb22576c535b3442fd6bd9c457775e0cc69f1951",
                          "3e07a131ef776640970bd4a2000202c04740c53bccb9ca9f76435d8967a459c496330193fc5bb0e3918a626a18205261f8715bfba6da4cf639e5654238d1a73e",
                          "698336fb3ddb03059c02ae960a7aa06f0dc77ae1a7fe8e473b3afa28b04cf3b49c954a2cd6d86fc6981a94223207d29dd37cf98d623128ebd047a9d088d5ae96",
                          "3137c954bb5db9fee3d09a9dbed659e8cc55e9167dcf390a194ad53a56f7caadada822853301494d2ee4f7cee19cd7ba4cf733c1a9f9c6587cfe77e05ea1fbef",
                          "e54ff008736b665a7f2b963a4e62a9881c65e47c4d8e247e22e2e55d9825d4718101a7355f0848889b5e25753f2df325f4c3b5a18c2b11831b92733fc95e3222",
                          "3cc60a3ab1d166bb44721c1dfd25e52090bb4561f60bbd961999a2b7a9ce074c44f7f5713563c9b5c963f5bc9054414480b99343176eb3f176c63ce4ae4609f2",
                          "3fe76b90c5e5aa286be74f8bb46eeca51cb222d8116b8c0d866ac85111a8019a846758d990b7387c52ee81500b4f8e224b54e38d039ece1b55c1c8ba9525c82d",
                          "d8bdc3ef0127d005753c0cbd5e2e9dea668aa754107d01462621bf8d4c7f9265857240579c9b3c74c98c70832640dc3fbb99d6f622ef5d26ab9e31ac95c870e5",
                          "ca4bd3077d42d4151cb9d7837a212aa39de79d421e2bc8e5950b920a98ed5d58565f2dff433d06d116e70131079d3c99bf67bef6dc65fcad26fa0ee2180161c3",
                          "38d1e19958515963c8abfb594fce598ed496d53183f77742425b375ff0a39efd5ff9b0ff38dc450eff27d619e596191ff3643e201a5d06f54672a93462fc335e"].map { $0.hex2Bytes }

        let publicKeys = ["f0fde0110193147e7961e61eeb22576c535b3442fd6bd9c457775e0cc69f1951",
                          "96330193fc5bb0e3918a626a18205261f8715bfba6da4cf639e5654238d1a73e",
                          "9c954a2cd6d86fc6981a94223207d29dd37cf98d623128ebd047a9d088d5ae96",
                          "ada822853301494d2ee4f7cee19cd7ba4cf733c1a9f9c6587cfe77e05ea1fbef",
                          "8101a7355f0848889b5e25753f2df325f4c3b5a18c2b11831b92733fc95e3222",
                          "44f7f5713563c9b5c963f5bc9054414480b99343176eb3f176c63ce4ae4609f2",
                          "846758d990b7387c52ee81500b4f8e224b54e38d039ece1b55c1c8ba9525c82d",
                          "857240579c9b3c74c98c70832640dc3fbb99d6f622ef5d26ab9e31ac95c870e5",
                          "565f2dff433d06d116e70131079d3c99bf67bef6dc65fcad26fa0ee2180161c3",
                          "5ff9b0ff38dc450eff27d619e596191ff3643e201a5d06f54672a93462fc335e"].map { $0.hex2Bytes }

        let signatures = ["40920d59cc06c723687a990d0da75fac9bbc4cedfc3b1b7abecd3f1bf7f5f250df07829b19f557fe915589ea5f117207531bd827a052a1b1c9df789d01f4980e",
                          "5e2de232e327f5436b8dc5042b273d9f6f9670ff8b9fea321bdc3fc318a63781fe30cc0510354b13cb3b0e32fad47c152c0b48eedb7a5bb5b5d3ad94eb1a020c",
                          "a1a9fb3163955c972c91a2d80d7e202bb21f0ba6f07a5feaf58739987e3554cc3907e3cc7144dedcc884d07cffeb94941866a64340acf0d667f3f491181b7a08",
                          "a09e2fe5db06176ba61d19cf7995fc94536b3ab42038b8bd2cec23af74578bdcff1bbbb63929d3f9a2a2d364e3ba36a23f390dfaf047a132b4a6952b7714250d",
                          "c8a81ee504a70be4478b292473cdd6f594694f09a8588091ce1c5e794c679655fd6d856b900951875fceacc4b38a580871238af449e7f464be398a6d39360a0c",
                          "46548d7e9a6e26f8d503d0acdd75534b40bc37f5ee0491c8bc9b7cc14f274b7d1fcbaa4bf6555792d34440e0587c9f180ef19ed00d517e5f085892bcae911d0e",
                          "11ec37dac50d1a44e371e4f39ecc1f8e00eb11fcd8b2a1a631fc6a554bcddb388b9d60e641ee74e59b2fcc83d63d09b8ce80f53f45b93d44594b724afc1d830f",
                          "8242de3dc7aaba746f1c214b4fd4233aa12120e38a9791058b6d9339d76ddbf8f8ca69186f3f12f7d7ef9d03cf254272b97363474746c29829bef59ceca8550b",
                          "ce44d28754ec793813ca48d683887a3ce99d83e7eacef3bc7778bcbb8e686de0fb7cf31c0170eac615da5a6e60504a67fc8f574b93bd3e3f249d61329adbae0c",
                          "e235b3d7088273bafd3dcf6f40c43a4e6be2aeb6e9eba48ac23e86331285efbe7d75acff1d0715749e96d1815a7dd6b35db793fd361dcabd67de1d341c3cd40e"].map { $0.hex2Bytes }

        for i in 0..<messages.count {
            let message = messages[i]
            let secretKey = secretKeys[i]
            let publicKey = publicKeys[i]
            let signature = signatures[i]
            var publickey = Bytes(count: type(of: self).publicKeyLength)
            ed25519_publickey(secretKey, &publickey)

            XCTAssertEqual(publicKey, publickey)
            let ret = ed25519_sign_open(message, Int(message.count), publicKey, signature) == 0
            XCTAssert(ret)
        }
    }

    func testBlake2b_20() {
        let originals = ["1c9c08c4f063214d8fe8e695be98ed3e59b7b34a225cbf58004fc8e014a1240c",
                         "f0f74272558cfb6c1a7eb02e2536ce62b55ecbd9e7e3114d0e7db65177cb6d68",
                         "bddb753d41c8217a10bb34c05936db6e901b9b9f1483b1cd3ac7cdfd323a738b",
                         "b04bfa07f1ebc35bc8512ecb85a34835a7a2f9c77c50bd03866642c5e26141eb",
                         "e3dfffed72292d1e7aa292d606e39e11b60ee9406c0ea0a412a4fbc54c8d3e27",
                         "036764612a11a0815f9c1eaa230e45eba0bfcfa2fa820a084894c9dee23ac31d",
                         "c87fd77b98d5f4c7712366dca4f0e395cd6cc0e3b2a71623f64bed6669e3085f",
                         "008c6974bcb68aabc0c215e3b3ae2d408b4c367d9d1fcd2a2de81f6c1a488fa8"].map { $0.hex2Bytes }

        let rets = ["3e1b20ce8613222458fa791e571637aedf2069c4",
                    "8e9c2a51c063ac7c40ad29e702fc3dfb2baa0263",
                    "bb310a07d81a832b80a2b55837de38997fee4383",
                    "aa6f1bdab6667080662e22f6dabf73f788e88add",
                    "b4d8eefc1c7c6d031ee8218bdbf4c5a2b4e89b7b",
                    "29f9aeaa593a65c205d081d41f06c260b6fa5fad",
                    "b90c6fd984afbfc0dd5da8602228c2907e890726",
                    "6af3e252cb88a98e149f756b18fee161537874a5"].map { $0.hex2Bytes }



        for i in 0..<originals.count {
            let original = originals[i]
            let ret = rets[i]


            let outLength = 20
            var out = Bytes(count: outLength)
            blake2b(original, UInt32(original.count), &out, outLength)
            XCTAssertEqual(ret, out)
        }
    }

    func testBlake2b_5() {
        let originals = ["3e1b20ce8613222458fa791e571637aedf2069c4",
                         "8e9c2a51c063ac7c40ad29e702fc3dfb2baa0263",
                         "bb310a07d81a832b80a2b55837de38997fee4383",
                         "aa6f1bdab6667080662e22f6dabf73f788e88add",
                         "b4d8eefc1c7c6d031ee8218bdbf4c5a2b4e89b7b",
                         "29f9aeaa593a65c205d081d41f06c260b6fa5fad",
                         "b90c6fd984afbfc0dd5da8602228c2907e890726",
                         "6af3e252cb88a98e149f756b18fee161537874a5"].map { $0.hex2Bytes }

        let rets = ["e5b58abe3b",
                    "77c415c833",
                    "f50e0843c7",
                    "8b14ca7d8c",
                    "765bb5f08b",
                    "cee385d445",
                    "198cafa3da",
                    "52070d0d99"].map { $0.hex2Bytes }

        for i in 0..<originals.count {
            let original = originals[i]
            let ret = rets[i]

            let outLength = 5
            var out = Bytes(count: outLength)
            blake2b(original, UInt32(original.count), &out, outLength)
            XCTAssertEqual(ret, out)
        }
    }
}

public typealias Bytes = Array<UInt8>

extension Array where Element == UInt8 {
    init (count bytes: Int) {
        self.init(repeating: 0, count: bytes)
    }
}

public extension String {
    var hex2Bytes: Bytes {

        if self.unicodeScalars.lazy.underestimatedCount % 2 != 0 {
            return []
        }

        var bytes = Bytes()
        bytes.reserveCapacity(self.unicodeScalars.lazy.underestimatedCount / 2)

        var buffer: UInt8?
        var skip = self.hasPrefix("0x") ? 2 : 0
        for char in self.unicodeScalars.lazy {
            guard skip == 0 else {
                skip -= 1
                continue
            }
            guard char.value >= 48 && char.value <= 102 else {
                return []
            }
            let v: UInt8
            let c: UInt8 = UInt8(char.value)
            switch c {
            case let c where c <= 57:
                v = c - 48
            case let c where c >= 65 && c <= 70:
                v = c - 55
            case let c where c >= 97:
                v = c - 87
            default:
                return []
            }
            if let b = buffer {
                bytes.append(b << 4 | v)
                buffer = nil
            } else {
                buffer = v
            }
        }
        if let b = buffer {
            bytes.append(b)
        }

        return bytes
    }
}
