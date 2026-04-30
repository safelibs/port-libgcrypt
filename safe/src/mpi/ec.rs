use std::ffi::{CStr, c_char, c_int, c_uint, c_void};
use std::ptr::null_mut;

use crate::context;
use crate::digest::algorithms;
use crate::error;
use crate::pubkey::encoding;
use crate::sexp;

use super::{Mpz, gcry_mpi};

#[derive(Clone, PartialEq, Eq)]
enum CurveKind {
    Weierstrass,
    Edwards,
    Montgomery { bits: usize, a24: u64 },
}

#[derive(Clone)]
pub(crate) struct Curve {
    pub(crate) name: &'static str,
    aliases: &'static [&'static str],
    kind: CurveKind,
    pub(crate) p: Mpz,
    a: Mpz,
    b: Mpz,
    n: Mpz,
    gx: Mpz,
    gy: Mpz,
    h: Mpz,
    pub(crate) field_bytes: usize,
}

#[derive(Clone)]
pub(crate) struct EcPoint {
    pub(crate) x: Option<Mpz>,
    pub(crate) y: Option<Mpz>,
    z: Option<Mpz>,
}

#[derive(Clone)]
pub(crate) struct EcContext {
    curve: Curve,
    q: Option<EcPoint>,
    d: Option<Mpz>,
}

impl EcPoint {
    fn infinity() -> Self {
        Self {
            x: None,
            y: None,
            z: None,
        }
    }

    fn affine(x: Mpz, y: Mpz) -> Self {
        Self {
            x: Some(x),
            y: Some(y),
            z: Some(Mpz::from_ui(1)),
        }
    }

    pub(crate) fn montgomery(x: Mpz) -> Self {
        Self {
            x: Some(x),
            y: None,
            z: Some(Mpz::from_ui(1)),
        }
    }

    fn is_infinity(&self) -> bool {
        self.x.is_none()
    }
}

fn hex(text: &str) -> Mpz {
    Mpz::from_hex(text)
}

fn curve_defs() -> Vec<Curve> {
    vec![
        Curve {
            name: "NIST P-192",
            aliases: &["prime192v1", "secp192r1", "nistp192", "1.2.840.10045.3.1.1"],
            kind: CurveKind::Weierstrass,
            p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF"),
            a: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"),
            b: hex("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1"),
            n: hex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831"),
            gx: hex("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012"),
            gy: hex("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811"),
            h: Mpz::from_ui(1),
            field_bytes: 24,
        },
        Curve {
            name: "NIST P-224",
            aliases: &["secp224r1", "nistp224", "1.3.132.0.33"],
            kind: CurveKind::Weierstrass,
            p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001"),
            a: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE"),
            b: hex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4"),
            n: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"),
            gx: hex("B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21"),
            gy: hex("BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34"),
            h: Mpz::from_ui(1),
            field_bytes: 28,
        },
        Curve {
            name: "NIST P-256",
            aliases: &["prime256v1", "secp256r1", "nistp256", "1.2.840.10045.3.1.7"],
            kind: CurveKind::Weierstrass,
            p: hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
            a: hex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
            b: hex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
            n: hex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
            gx: hex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
            gy: hex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
            h: Mpz::from_ui(1),
            field_bytes: 32,
        },
        Curve {
            name: "NIST P-384",
            aliases: &["secp384r1", "nistp384", "1.3.132.0.34"],
            kind: CurveKind::Weierstrass,
            p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"),
            a: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC"),
            b: hex("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF"),
            n: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"),
            gx: hex("AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"),
            gy: hex("3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"),
            h: Mpz::from_ui(1),
            field_bytes: 48,
        },
        Curve {
            name: "NIST P-521",
            aliases: &["secp521r1", "nistp521", "1.3.132.0.35"],
            kind: CurveKind::Weierstrass,
            p: hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            a: hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"),
            b: hex("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"),
            n: hex("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409"),
            gx: hex("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
            gy: hex("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"),
            h: Mpz::from_ui(1),
            field_bytes: 66,
        },
        Curve {
            name: "brainpoolP160r1",
            aliases: &["1.3.36.3.3.2.8.1.1.1"],
            kind: CurveKind::Weierstrass,
            p: hex("E95E4A5F737059DC60DFC7AD95B3D8139515620F"),
            a: hex("340E7BE2A280EB74E2BE61BADA745D97E8F7C300"),
            b: hex("1E589A8595423412134FAA2DBDEC95C8D8675E58"),
            n: hex("E95E4A5F737059DC60DF5991D45029409E60FC09"),
            gx: hex("BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3"),
            gy: hex("1667CB477A1A8EC338F94741669C976316DA6321"),
            h: Mpz::from_ui(1),
            field_bytes: 20,
        },
        Curve {
            name: "brainpoolP192r1",
            aliases: &["1.3.36.3.3.2.8.1.1.3"],
            kind: CurveKind::Weierstrass,
            p: hex("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297"),
            a: hex("6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EF"),
            b: hex("469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9"),
            n: hex("C302F41D932A36CDA7A3462F9E9E916B5BE8F1029AC4ACC1"),
            gx: hex("C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6"),
            gy: hex("14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8F"),
            h: Mpz::from_ui(1),
            field_bytes: 24,
        },
        Curve {
            name: "brainpoolP224r1",
            aliases: &["1.3.36.3.3.2.8.1.1.5"],
            kind: CurveKind::Weierstrass,
            p: hex("D7C134AA264366862A18302575D1D787B09F075797DA89F57EC8C0FF"),
            a: hex("68A5E62CA9CE6C1C299803A6C1530B514E182AD8B0042A59CAD29F43"),
            b: hex("2580F63CCFE44138870713B1A92369E33E2135D266DBB372386C400B"),
            n: hex("D7C134AA264366862A18302575D0FB98D116BC4B6DDEBCA3A5A7939F"),
            gx: hex("0D9029AD2C7E5CF4340823B2A87DC68C9E4CE3174C1E6EFDEE12C07D"),
            gy: hex("58AA56F772C0726F24C6B89E4ECDAC24354B9E99CAA3F6D3761402CD"),
            h: Mpz::from_ui(1),
            field_bytes: 28,
        },
        Curve {
            name: "brainpoolP256r1",
            aliases: &["1.3.36.3.3.2.8.1.1.7"],
            kind: CurveKind::Weierstrass,
            p: hex("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"),
            a: hex("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"),
            b: hex("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"),
            n: hex("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"),
            gx: hex("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"),
            gy: hex("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"),
            h: Mpz::from_ui(1),
            field_bytes: 32,
        },
        Curve {
            name: "brainpoolP320r1",
            aliases: &["1.3.36.3.3.2.8.1.1.9"],
            kind: CurveKind::Weierstrass,
            p: hex(
                "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27",
            ),
            a: hex(
                "3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4",
            ),
            b: hex(
                "520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6",
            ),
            n: hex(
                "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311",
            ),
            gx: hex(
                "43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611",
            ),
            gy: hex(
                "14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1",
            ),
            h: Mpz::from_ui(1),
            field_bytes: 40,
        },
        Curve {
            name: "brainpoolP384r1",
            aliases: &["1.3.36.3.3.2.8.1.1.11"],
            kind: CurveKind::Weierstrass,
            p: hex(
                "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53",
            ),
            a: hex(
                "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826",
            ),
            b: hex(
                "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11",
            ),
            n: hex(
                "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565",
            ),
            gx: hex(
                "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E",
            ),
            gy: hex(
                "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315",
            ),
            h: Mpz::from_ui(1),
            field_bytes: 48,
        },
        Curve {
            name: "brainpoolP512r1",
            aliases: &["1.3.36.3.3.2.8.1.1.13"],
            kind: CurveKind::Weierstrass,
            p: hex(
                "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3",
            ),
            a: hex(
                "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA",
            ),
            b: hex(
                "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723",
            ),
            n: hex(
                "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069",
            ),
            gx: hex(
                "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822",
            ),
            gy: hex(
                "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892",
            ),
            h: Mpz::from_ui(1),
            field_bytes: 64,
        },
        Curve {
            name: "Ed25519",
            aliases: &["1.3.6.1.4.1.11591.15.1", "1.3.101.112"],
            kind: CurveKind::Edwards,
            p: hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"),
            a: hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC"),
            b: hex("52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3"),
            n: hex("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"),
            gx: hex("216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"),
            gy: hex("6666666666666666666666666666666666666666666666666666666666666658"),
            h: Mpz::from_ui(8),
            field_bytes: 32,
        },
        Curve {
            name: "Ed448",
            aliases: &["1.3.101.113"],
            kind: CurveKind::Edwards,
            p: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            ),
            a: Mpz::from_ui(1),
            b: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756",
            ),
            n: hex(
                "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3",
            ),
            gx: hex(
                "4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E",
            ),
            gy: hex(
                "693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14",
            ),
            h: Mpz::from_ui(4),
            field_bytes: 57,
        },
        Curve {
            name: "Curve25519",
            aliases: &["X25519", "1.3.6.1.4.1.3029.1.5.1", "1.3.101.110"],
            kind: CurveKind::Montgomery { bits: 255, a24: 121665 },
            p: hex("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"),
            a: Mpz::from_ui(486662),
            b: Mpz::from_ui(1),
            n: hex("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"),
            gx: Mpz::from_ui(9),
            gy: Mpz::from_ui(0),
            h: Mpz::from_ui(8),
            field_bytes: 32,
        },
        Curve {
            name: "X448",
            aliases: &["1.3.101.111"],
            kind: CurveKind::Montgomery { bits: 448, a24: 39081 },
            p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
            a: Mpz::from_ui(156326),
            b: Mpz::from_ui(1),
            n: hex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3"),
            gx: Mpz::from_ui(5),
            gy: Mpz::from_ui(0),
            h: Mpz::from_ui(4),
            field_bytes: 56,
        },
        Curve {
            name: "GOST2001-test",
            aliases: &["1.2.643.2.2.35.0"],
            kind: CurveKind::Weierstrass,
            p: hex("8000000000000000000000000000000000000000000000000000000000000431"),
            a: hex("0000000000000000000000000000000000000000000000000000000000000007"),
            b: hex("5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E"),
            n: hex("8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3"),
            gx: hex("0000000000000000000000000000000000000000000000000000000000000002"),
            gy: hex("08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8"),
            h: Mpz::from_ui(1),
            field_bytes: 32,
        },
        Curve {
            name: "GOST2001-CryptoPro-A",
            aliases: &[
                "1.2.643.2.2.35.1",
                "GOST2001-CryptoPro-XchA",
                "1.2.643.2.2.36.0",
                "GOST2012-256-tc26-B",
                "1.2.643.7.1.2.1.1.2",
            ],
            kind: CurveKind::Weierstrass,
            p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
            a: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
            b: hex("00000000000000000000000000000000000000000000000000000000000000A6"),
            n: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
            gx: hex("0000000000000000000000000000000000000000000000000000000000000001"),
            gy: hex("8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
            h: Mpz::from_ui(1),
            field_bytes: 32,
        },
        Curve {
            name: "GOST2001-CryptoPro-B",
            aliases: &[
                "1.2.643.2.2.35.2",
                "GOST2012-256-tc26-C",
                "1.2.643.7.1.2.1.1.3",
            ],
            kind: CurveKind::Weierstrass,
            p: hex("8000000000000000000000000000000000000000000000000000000000000C99"),
            a: hex("8000000000000000000000000000000000000000000000000000000000000C96"),
            b: hex("3E1AF419A269A5F866A7D3C25C3DF80AE979259373FF2B182F49D4CE7E1BBC8B"),
            n: hex("800000000000000000000000000000015F700CFFF1A624E5E497161BCC8A198F"),
            gx: hex("0000000000000000000000000000000000000000000000000000000000000001"),
            gy: hex("3FA8124359F96680B83D1C3EB2C070E5C545C9858D03ECFB744BF8D717717EFC"),
            h: Mpz::from_ui(1),
            field_bytes: 32,
        },
        Curve {
            name: "GOST2001-CryptoPro-C",
            aliases: &[
                "1.2.643.2.2.35.3",
                "GOST2001-CryptoPro-XchB",
                "1.2.643.2.2.36.1",
                "GOST2012-256-tc26-D",
                "1.2.643.7.1.2.1.1.4",
            ],
            kind: CurveKind::Weierstrass,
            p: hex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D759B"),
            a: hex("9B9F605F5A858107AB1EC85E6B41C8AACF846E86789051D37998F7B9022D7598"),
            b: hex("000000000000000000000000000000000000000000000000000000000000805A"),
            n: hex("9B9F605F5A858107AB1EC85E6B41C8AA582CA3511EDDFB74F02F3A6598980BB9"),
            gx: hex("0000000000000000000000000000000000000000000000000000000000000000"),
            gy: hex("41ECE55743711A8C3CBF3783CD08C0EE4D4DC440D4641A8F366E550DFDB3BB67"),
            h: Mpz::from_ui(1),
            field_bytes: 32,
        },
        Curve {
            name: "GOST2012-256-A",
            aliases: &["GOST2012-256-tc26-A", "1.2.643.7.1.2.1.1.1"],
            kind: CurveKind::Weierstrass,
            p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
            a: hex("C2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"),
            b: hex("295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"),
            n: hex("400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
            gx: hex("91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"),
            gy: hex("32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"),
            h: Mpz::from_ui(4),
            field_bytes: 32,
        },
        Curve {
            name: "GOST2012-512-test",
            aliases: &["GOST2012-test", "1.2.643.7.1.2.1.2.0"],
            kind: CurveKind::Weierstrass,
            p: hex(
                "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373",
            ),
            a: hex("0000000000000000000000000000000000000000000000000000000000000007"),
            b: hex(
                "1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC",
            ),
            n: hex(
                "4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF",
            ),
            gx: hex(
                "24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A",
            ),
            gy: hex(
                "2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E",
            ),
            h: Mpz::from_ui(1),
            field_bytes: 64,
        },
        Curve {
            name: "GOST2012-512-tc26-A",
            aliases: &["GOST2012-tc26-A", "1.2.643.7.1.2.1.2.1"],
            kind: CurveKind::Weierstrass,
            p: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
            ),
            a: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4",
            ),
            b: hex(
                "E8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760",
            ),
            n: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275",
            ),
            gx: hex(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003",
            ),
            gy: hex(
                "7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4",
            ),
            h: Mpz::from_ui(1),
            field_bytes: 64,
        },
        Curve {
            name: "GOST2012-512-tc26-B",
            aliases: &["GOST2012-tc26-B", "1.2.643.7.1.2.1.2.2"],
            kind: CurveKind::Weierstrass,
            p: hex(
                "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006F",
            ),
            a: hex(
                "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006C",
            ),
            b: hex(
                "687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116",
            ),
            n: hex(
                "800000000000000000000000000000000000000000000000000000000000000149A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD",
            ),
            gx: hex(
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002",
            ),
            gy: hex(
                "1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD",
            ),
            h: Mpz::from_ui(1),
            field_bytes: 64,
        },
        Curve {
            name: "GOST2012-512-tc26-C",
            aliases: &["1.2.643.7.1.2.1.2.3"],
            kind: CurveKind::Weierstrass,
            p: hex(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7",
            ),
            a: hex(
                "DC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E143064546E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3",
            ),
            b: hex(
                "B4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE038CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1",
            ),
            n: hex(
                "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED",
            ),
            gx: hex(
                "E2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043AA27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148",
            ),
            gy: hex(
                "F5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9BE18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F",
            ),
            h: Mpz::from_ui(4),
            field_bytes: 64,
        },
        Curve {
            name: "sm2p256v1",
            aliases: &["1.2.156.10197.1.301"],
            kind: CurveKind::Weierstrass,
            p: hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"),
            a: hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"),
            b: hex("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"),
            n: hex("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"),
            gx: hex("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"),
            gy: hex("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"),
            h: Mpz::from_ui(1),
            field_bytes: 32,
        },
        Curve {
            name: "secp256k1",
            aliases: &["1.3.132.0.10"],
            kind: CurveKind::Weierstrass,
            p: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
            a: Mpz::from_ui(0),
            b: Mpz::from_ui(7),
            n: hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            gx: hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
            gy: hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
            h: Mpz::from_ui(1),
            field_bytes: 32,
        },
    ]
}

pub(crate) fn curve_by_name(name: &str) -> Option<Curve> {
    let needle = name.trim_matches('"');
    curve_defs().into_iter().find(|curve| {
        curve.name.eq_ignore_ascii_case(needle)
            || curve
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(needle))
    })
}

fn set_target(target: *mut gcry_mpi, value: Mpz) {
    if target.is_null() {
        return;
    }
    let tmp = gcry_mpi::from_numeric(value, false);
    super::gcry_mpi_set(target, tmp);
    super::gcry_mpi_release(tmp);
}

fn mpi_to_mpz(ptr: *mut gcry_mpi) -> Option<Mpz> {
    let value = unsafe { gcry_mpi::as_ref(ptr) }?;
    Mpz::from_mpi(value)
}

fn point_from_raw(point: *mut c_void) -> Option<&'static EcPoint> {
    unsafe { point.cast::<EcPoint>().as_ref() }
}

fn point_from_raw_mut(point: *mut c_void) -> Option<&'static mut EcPoint> {
    unsafe { point.cast::<EcPoint>().as_mut() }
}

fn fixed_len_be(value: &Mpz, len: usize) -> Vec<u8> {
    let mut bytes = value.to_be();
    if bytes.len() > len {
        bytes = bytes[bytes.len() - len..].to_vec();
    }
    if bytes.len() < len {
        let mut padded = vec![0u8; len - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    bytes
}

fn shake256(data: &[u8], len: usize) -> Option<Vec<u8>> {
    let mut state = algorithms::HashState::new(algorithms::GCRY_MD_SHAKE256)?;
    state.update(data);
    state.xof_vec(len)
}

fn private_scalar_for_curve(curve: &Curve, d: &Mpz) -> Mpz {
    if curve.name == "Ed25519" {
        let seed = fixed_len_be(d, 32);
        if let Some(digest) = algorithms::digest_once(algorithms::GCRY_MD_SHA512, &seed) {
            let mut scalar = digest[..32].to_vec();
            scalar[0] &= 248;
            scalar[31] &= 63;
            scalar[31] |= 64;
            return Mpz::from_le(&scalar);
        }
    } else if curve.name == "Ed448" {
        let seed = fixed_len_be(d, 57);
        if let Some(digest) = shake256(&seed, 114) {
            let mut scalar = digest[..57].to_vec();
            scalar[0] &= 252;
            scalar[55] |= 128;
            scalar[56] = 0;
            return Mpz::from_le(&scalar);
        }
    }
    d.clone()
}

fn mod_div(num: &Mpz, den: &Mpz, p: &Mpz) -> Option<Mpz> {
    Some(num.mod_mul(&den.invert(p)?, p))
}

fn weier_add(curve: &Curve, left: &EcPoint, right: &EcPoint) -> EcPoint {
    if left.is_infinity() {
        return right.clone();
    }
    if right.is_infinity() {
        return left.clone();
    }
    let p = &curve.p;
    let x1 = left.x.as_ref().unwrap();
    let y1 = left.y.as_ref().unwrap();
    let x2 = right.x.as_ref().unwrap();
    let y2 = right.y.as_ref().unwrap();
    if x1.cmp(x2) == 0 {
        if y1.mod_add(y2, p).is_zero() {
            return EcPoint::infinity();
        }
        if y1.is_zero() {
            return EcPoint::infinity();
        }
        let num = x1.mod_square(p).mul_ui(3).mod_add(&curve.a, p);
        let den = y1.mul_ui(2).modulo(p);
        let Some(lambda) = mod_div(&num, &den, p) else {
            return EcPoint::infinity();
        };
        let x3 = lambda.mod_square(p).mod_sub(x1, p).mod_sub(x1, p);
        let y3 = lambda.mod_mul(&x1.mod_sub(&x3, p), p).mod_sub(y1, p);
        EcPoint::affine(x3, y3)
    } else {
        let num = y2.mod_sub(y1, p);
        let den = x2.mod_sub(x1, p);
        let Some(lambda) = mod_div(&num, &den, p) else {
            return EcPoint::infinity();
        };
        let x3 = lambda.mod_square(p).mod_sub(x1, p).mod_sub(x2, p);
        let y3 = lambda.mod_mul(&x1.mod_sub(&x3, p), p).mod_sub(y1, p);
        EcPoint::affine(x3, y3)
    }
}

fn ed_add(curve: &Curve, left: &EcPoint, right: &EcPoint) -> EcPoint {
    let p = &curve.p;
    let x1 = left.x.as_ref().unwrap();
    let y1 = left.y.as_ref().unwrap();
    let x2 = right.x.as_ref().unwrap();
    let y2 = right.y.as_ref().unwrap();
    let x1x2 = x1.mod_mul(x2, p);
    let y1y2 = y1.mod_mul(y2, p);
    let dxxyy = curve.b.mod_mul(&x1x2, p).mod_mul(&y1y2, p);
    let one = Mpz::from_ui(1);
    let x_num = x1.mod_mul(y2, p).mod_add(&y1.mod_mul(x2, p), p);
    let y_num = y1y2.mod_sub(&curve.a.mod_mul(&x1x2, p), p);
    let x_den = one.mod_add(&dxxyy, p);
    let y_den = one.mod_sub(&dxxyy, p);
    let x3 = mod_div(&x_num, &x_den, p).unwrap_or_else(|| Mpz::from_ui(0));
    let y3 = mod_div(&y_num, &y_den, p).unwrap_or_else(|| Mpz::from_ui(1));
    EcPoint::affine(x3, y3)
}

fn point_add(curve: &Curve, left: &EcPoint, right: &EcPoint) -> EcPoint {
    match curve.kind {
        CurveKind::Weierstrass => weier_add(curve, left, right),
        CurveKind::Edwards => ed_add(curve, left, right),
        CurveKind::Montgomery { .. } => right.clone(),
    }
}

pub(crate) fn scalar_mul(curve: &Curve, scalar: &Mpz, point: &EcPoint) -> EcPoint {
    if matches!(curve.kind, CurveKind::Montgomery { .. }) {
        let x = point.x.as_ref().cloned().unwrap_or_else(|| curve.gx.clone());
        return EcPoint::montgomery(montgomery_mul(curve, scalar, &x));
    }
    let mut acc = if curve.kind == CurveKind::Edwards {
        EcPoint::affine(Mpz::from_ui(0), Mpz::from_ui(1))
    } else {
        EcPoint::infinity()
    };
    for bit in (0..scalar.bits()).rev() {
        acc = point_add(curve, &acc, &acc);
        if scalar.test_bit(bit) {
            acc = point_add(curve, &acc, point);
        }
    }
    acc
}

pub(crate) fn scalar_mul_secret(curve: &Curve, scalar: &Mpz, point: &EcPoint) -> EcPoint {
    if matches!(curve.kind, CurveKind::Montgomery { .. }) {
        let x = point.x.as_ref().cloned().unwrap_or_else(|| curve.gx.clone());
        return EcPoint::montgomery(montgomery_mul(curve, scalar, &x));
    }
    let mut acc = if curve.kind == CurveKind::Edwards {
        EcPoint::affine(Mpz::from_ui(0), Mpz::from_ui(1))
    } else {
        EcPoint::infinity()
    };
    let total_bits = curve.n.bits().max(curve.field_bytes * 8).max(scalar.bits());
    for bit in (0..total_bits).rev() {
        acc = point_add(curve, &acc, &acc);
        if scalar.test_bit(bit) {
            acc = point_add(curve, &acc, point);
        }
    }
    acc
}

fn montgomery_mul(curve: &Curve, scalar: &Mpz, u: &Mpz) -> Mpz {
    let CurveKind::Montgomery { bits, a24 } = curve.kind else {
        return Mpz::from_ui(0);
    };
    let p = &curve.p;
    let mut k = scalar.to_le_padded(curve.field_bytes);
    if bits == 255 {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
    } else {
        k[0] &= 252;
        k[55] |= 128;
    }
    let x1 = if bits == 255 {
        let mut u_bytes = u.to_le_padded(curve.field_bytes);
        if let Some(last) = u_bytes.last_mut() {
            *last &= 0x7f;
        }
        Mpz::from_le(&u_bytes)
    } else {
        u.clone()
    }
    .modulo(p);
    let mut x2 = Mpz::from_ui(1);
    let mut z2 = Mpz::from_ui(0);
    let mut x3 = x1.clone();
    let mut z3 = Mpz::from_ui(1);
    let mut swap = false;
    for t in (0..bits).rev() {
        let kt = (k[t / 8] >> (t % 8)) & 1 != 0;
        if kt != swap {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
            swap = kt;
        }
        let a = x2.mod_add(&z2, p);
        let aa = a.mod_square(p);
        let b = x2.mod_sub(&z2, p);
        let bb = b.mod_square(p);
        let e = aa.mod_sub(&bb, p);
        let c = x3.mod_add(&z3, p);
        let d = x3.mod_sub(&z3, p);
        let da = d.mod_mul(&a, p);
        let cb = c.mod_mul(&b, p);
        let da_cb_sum = da.mod_add(&cb, p);
        let da_cb_diff = da.mod_sub(&cb, p);
        x3 = da_cb_sum.mod_square(p);
        z3 = x1.mod_mul(&da_cb_diff.mod_square(p), p);
        x2 = aa.mod_mul(&bb, p);
        z2 = e.mod_mul(&aa.mod_add(&e.mul_ui(a24).modulo(p), p), p);
    }
    if swap {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }
    x2.mod_mul(&z2.invert(p).unwrap_or_else(|| Mpz::from_ui(0)), p)
}

pub(crate) fn base_point(curve: &Curve) -> EcPoint {
    if matches!(curve.kind, CurveKind::Montgomery { .. }) {
        EcPoint::montgomery(curve.gx.clone())
    } else {
        EcPoint::affine(curve.gx.clone(), curve.gy.clone())
    }
}

pub(crate) fn decode_point(curve: &Curve, bytes: &[u8]) -> Option<EcPoint> {
    if matches!(curve.kind, CurveKind::Montgomery { .. }) {
        let raw = if bytes.first() == Some(&0x40) {
            &bytes[1..]
        } else {
            bytes
        };
        return Some(EcPoint::montgomery(Mpz::from_le(raw)));
    }
    if curve.kind == CurveKind::Edwards
        && (bytes.len() == curve.field_bytes
            || ((bytes.first() == Some(&0x40) || bytes.first() == Some(&0x04))
                && bytes.len() == curve.field_bytes + 1))
    {
        let raw = if bytes.len() == curve.field_bytes + 1
            && (bytes.first() == Some(&0x40) || bytes.first() == Some(&0x04))
        {
            &bytes[1..]
        } else {
            bytes
        };
        let mut y_bytes = raw.to_vec();
        let sign = y_bytes.last().map(|byte| byte >> 7).unwrap_or(0);
        if let Some(last) = y_bytes.last_mut() {
            *last &= 0x7f;
        }
        let y = Mpz::from_le(&y_bytes);
        let p = &curve.p;
        let one = Mpz::from_ui(1);
        let y2 = y.mod_square(p);
        let num = one.mod_sub(&y2, p);
        let den = curve.a.mod_sub(&curve.b.mod_mul(&y2, p), p);
        let x2 = mod_div(&num, &den, p)?;
        let mut x = if p.rem_ui(8) == 5 {
            x2.powm(&p.add_ui(3).shr(3), p)
        } else {
            x2.powm(&p.add_ui(1).shr(2), p)
        };
        if p.rem_ui(8) == 5 && x.mod_square(p).cmp(&x2) != 0 {
            let i = Mpz::from_ui(2).powm(&p.sub_ui(1).shr(2), p);
            x = x.mod_mul(&i, p);
        }
        if x.mod_square(p).cmp(&x2) != 0 {
            return None;
        }
        if (x.rem_ui(2) as u8) != sign {
            x = x.mod_neg(p);
        }
        return Some(EcPoint::affine(x, y));
    }
    if bytes.first() == Some(&4) {
        let coord_len = (bytes.len() - 1) / 2;
        let x = Mpz::from_be(&bytes[1..1 + coord_len]);
        let y = Mpz::from_be(&bytes[1 + coord_len..]);
        return Some(EcPoint::affine(x, y));
    }
    if (bytes.first() == Some(&0x02) || bytes.first() == Some(&0x03))
        && bytes.len() == curve.field_bytes + 1
        && curve.kind == CurveKind::Weierstrass
    {
        let x = Mpz::from_be(&bytes[1..]);
        let p = &curve.p;
        let x3 = x.mod_square(p).mod_mul(&x, p);
        let rhs = x3.mod_add(&curve.a.mod_mul(&x, p), p).mod_add(&curve.b, p);
        let mut y = if p.rem_ui(4) == 3 {
            rhs.powm(&p.add_ui(1).shr(2), p)
        } else {
            return None;
        };
        let want_odd = bytes[0] == 0x03;
        if (y.rem_ui(2) == 1) != want_odd {
            y = y.mod_neg(p);
        }
        return Some(EcPoint::affine(x, y));
    }
    None
}

pub(crate) fn encode_point(curve: &Curve, point: &EcPoint) -> Vec<u8> {
    if point.is_infinity() {
        return vec![0];
    }
    if matches!(curve.kind, CurveKind::Montgomery { .. }) {
        let mut out = vec![0x40];
        out.extend_from_slice(&point.x.as_ref().unwrap().to_le_padded(curve.field_bytes));
        return out;
    }
    let mut out = Vec::with_capacity(1 + 2 * curve.field_bytes);
    out.push(4);
    out.extend_from_slice(&point.x.as_ref().unwrap().to_be_padded(curve.field_bytes));
    out.extend_from_slice(&point.y.as_ref().unwrap().to_be_padded(curve.field_bytes));
    out
}

pub(crate) fn encode_eddsa(point: &EcPoint, bytes: usize) -> Vec<u8> {
    let mut y = point.y.as_ref().unwrap().to_le_padded(bytes);
    if point.x.as_ref().unwrap().rem_ui(2) != 0 {
        if let Some(last) = y.last_mut() {
            *last |= 0x80;
        }
    }
    y
}

fn curve_point(curve: &Curve, point: &EcPoint) -> bool {
    if point.is_infinity() {
        return true;
    }
    let p = &curve.p;
    let x = point.x.as_ref().unwrap();
    if matches!(curve.kind, CurveKind::Montgomery { .. }) {
        return x.cmp(p) < 0;
    }
    let y = point.y.as_ref().unwrap();
    if x.cmp(p) >= 0 || y.cmp(p) >= 0 {
        return false;
    }
    if curve.kind == CurveKind::Edwards {
        let lhs = curve.a.mod_mul(&x.mod_square(p), p).mod_add(&y.mod_square(p), p);
        let rhs = Mpz::from_ui(1).mod_add(&curve.b.mod_mul(&x.mod_square(p), p).mod_mul(&y.mod_square(p), p), p);
        lhs.cmp(&rhs) == 0
    } else {
        let lhs = y.mod_square(p);
        let rhs = x.mod_square(p).mod_mul(x, p).mod_add(&curve.a.mod_mul(x, p), p).mod_add(&curve.b, p);
        lhs.cmp(&rhs) == 0
    }
}

fn context_from_key(keyparam: *mut sexp::gcry_sexp, curvename: *const c_char) -> Result<EcContext, u32> {
    let name = if !curvename.is_null() {
        unsafe { CStr::from_ptr(curvename) }.to_string_lossy().into_owned()
    } else if let Some(p) = encoding::token_mpz(keyparam, "p") {
        let Some(a) = encoding::token_mpz(keyparam, "a") else {
            return Err(error::GPG_ERR_EINVAL);
        };
        if p.is_zero() || a.is_zero() {
            return Err(error::GPG_ERR_EINVAL);
        }
        let field_bytes = p.bits().div_ceil(8).max(1);
        return Ok(EcContext {
            curve: Curve {
                name: "custom",
                aliases: &[],
                kind: CurveKind::Weierstrass,
                p,
                a,
                b: Mpz::from_ui(0),
                n: Mpz::from_ui(0),
                gx: Mpz::from_ui(0),
                gy: Mpz::from_ui(0),
                h: Mpz::from_ui(1),
                field_bytes,
            },
            q: None,
            d: None,
        });
    } else {
        encoding::token_string(keyparam, "curve").ok_or(error::GPG_ERR_EINVAL)?
    };
    let curve = curve_by_name(&name).ok_or(error::GPG_ERR_INV_NAME)?;
    let q = encoding::token_bytes_from_mpi(keyparam, "q").and_then(|bytes| decode_point(&curve, &bytes));
    let d = encoding::token_mpz(keyparam, "d");
    let q = q.or_else(|| {
        d.as_ref()
            .map(|d| scalar_mul_secret(&curve, &private_scalar_for_curve(&curve, d), &base_point(&curve)))
    });
    Ok(EcContext { curve, q, d })
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_point_new(_nbits: c_uint) -> *mut c_void {
    Box::into_raw(Box::new(EcPoint::infinity())).cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_point_release(point: *mut c_void) {
    if !point.is_null() {
        unsafe { drop(Box::from_raw(point.cast::<EcPoint>())) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_point_copy(point: *mut c_void) -> *mut c_void {
    point_from_raw(point)
        .map(|point| Box::into_raw(Box::new(point.clone())).cast())
        .unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_point_get(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
    point: *mut c_void,
) {
    let Some(point) = point_from_raw(point) else {
        set_target(x, Mpz::from_ui(0));
        set_target(y, Mpz::from_ui(0));
        set_target(z, Mpz::from_ui(0));
        return;
    };
    set_target(x, point.x.clone().unwrap_or_else(|| Mpz::from_ui(0)));
    set_target(y, point.y.clone().unwrap_or_else(|| Mpz::from_ui(0)));
    set_target(z, point.z.clone().unwrap_or_else(|| Mpz::from_ui(0)));
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_point_snatch_get(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
    point: *mut c_void,
) {
    gcry_mpi_point_get(x, y, z, point);
    gcry_mpi_point_release(point);
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_point_set(
    point: *mut c_void,
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
) -> *mut c_void {
    let target = if point.is_null() {
        gcry_mpi_point_new(0)
    } else {
        point
    };
    let Some(target_ref) = point_from_raw_mut(target) else {
        return null_mut();
    };
    let z_is_zero = mpi_to_mpz(z).is_none_or(|z| z.is_zero());
    *target_ref = if z_is_zero {
        EcPoint::infinity()
    } else {
        let x = mpi_to_mpz(x).unwrap_or_else(|| Mpz::from_ui(0));
        let y = mpi_to_mpz(y);
        let z = mpi_to_mpz(z);
        EcPoint {
            x: Some(x),
            y,
            z,
        }
    };
    target
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_point_snatch_set(
    point: *mut c_void,
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
) -> *mut c_void {
    let result = gcry_mpi_point_set(point, x, y, z);
    super::gcry_mpi_release(x);
    super::gcry_mpi_release(y);
    super::gcry_mpi_release(z);
    result
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_new(
    r_ctx: *mut *mut c_void,
    keyparam: *mut sexp::gcry_sexp,
    curvename: *const c_char,
) -> u32 {
    if r_ctx.is_null() {
        return encoding::err(error::GPG_ERR_INV_ARG);
    }
    unsafe { *r_ctx = null_mut() };
    match context_from_key(keyparam, curvename) {
        Ok(ctx) => unsafe {
            *r_ctx = context::new_ec(ctx);
            0
        },
        Err(code) => encoding::err(code),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_get_mpi(
    name: *const c_char,
    ctx: *mut c_void,
    _copy: c_int,
) -> *mut gcry_mpi {
    let Some(ctx) = (unsafe { context::ec_ref(ctx) }) else {
        return null_mut();
    };
    let name = if name.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("")
    };
    let value = match name.to_ascii_lowercase().as_str() {
        "p" => Some(ctx.curve.p.clone()),
        "a" => Some(ctx.curve.a.clone()),
        "b" => Some(ctx.curve.b.clone()),
        "n" => Some(ctx.curve.n.clone()),
        "h" => Some(ctx.curve.h.clone()),
        "g.x" => Some(ctx.curve.gx.clone()),
        "g.y" => Some(ctx.curve.gy.clone()),
        "d" => ctx.d.clone(),
        "q" => ctx.q.as_ref().map(|q| Mpz::from_be(&encode_point(&ctx.curve, q))),
        "q@eddsa" => ctx.q.as_ref().map(|q| Mpz::from_be(&encode_eddsa(q, ctx.curve.field_bytes))),
        _ => None,
    };
    value
        .map(|value| gcry_mpi::from_numeric(value, false))
        .unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_get_point(
    name: *const c_char,
    ctx: *mut c_void,
    _copy: c_int,
) -> *mut c_void {
    let Some(ctx) = (unsafe { context::ec_ref(ctx) }) else {
        return null_mut();
    };
    let name = if name.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("")
    };
    let point = if name.eq_ignore_ascii_case("g") {
        Some(base_point(&ctx.curve))
    } else if name.eq_ignore_ascii_case("q") {
        ctx.q.clone()
    } else {
        None
    };
    point
        .map(|point| Box::into_raw(Box::new(point)).cast())
        .unwrap_or(null_mut())
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_set_mpi(
    name: *const c_char,
    newvalue: *mut gcry_mpi,
    ctx: *mut c_void,
) -> u32 {
    let Some(ctx) = (unsafe { context::ec_mut(ctx) }) else {
        return encoding::err(error::GPG_ERR_INV_ARG);
    };
    let name = if name.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("")
    };
    if name.eq_ignore_ascii_case("d") {
        if newvalue.is_null() {
            ctx.d = None;
            if ctx.curve.kind == CurveKind::Edwards {
                ctx.q = None;
            }
            return 0;
        }
        ctx.d = mpi_to_mpz(newvalue);
        ctx.q = ctx
            .d
            .as_ref()
            .map(|d| scalar_mul_secret(&ctx.curve, &private_scalar_for_curve(&ctx.curve, d), &base_point(&ctx.curve)));
        return 0;
    }
    if name.eq_ignore_ascii_case("q") {
        if newvalue.is_null() {
            ctx.q = None;
            return 0;
        }
        let bytes = unsafe { gcry_mpi::as_ref(newvalue) }
            .and_then(|mpi| {
                mpi.opaque()
                    .map(|opaque| opaque.as_slice().to_vec())
                    .or_else(|| Mpz::from_mpi(mpi).map(|value| value.to_be()))
            })
            .unwrap_or_default();
        ctx.q = decode_point(&ctx.curve, &bytes);
        return if ctx.q.is_some() { 0 } else { encoding::err(error::GPG_ERR_INV_OBJ) };
    }
    encoding::err(error::GPG_ERR_INV_NAME)
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_set_point(
    name: *const c_char,
    newvalue: *mut c_void,
    ctx: *mut c_void,
) -> u32 {
    let Some(ctx) = (unsafe { context::ec_mut(ctx) }) else {
        return encoding::err(error::GPG_ERR_INV_ARG);
    };
    let name = if name.is_null() {
        ""
    } else {
        unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("")
    };
    if name.eq_ignore_ascii_case("q") {
        ctx.q = point_from_raw(newvalue).cloned();
        0
    } else if name.eq_ignore_ascii_case("g") {
        0
    } else {
        encoding::err(error::GPG_ERR_INV_NAME)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_decode_point(
    result: *mut c_void,
    value: *mut gcry_mpi,
    ctx: *mut c_void,
) -> u32 {
    let Some(ctx) = (unsafe { context::ec_ref(ctx) }) else {
        return encoding::err(error::GPG_ERR_INV_ARG);
    };
    let bytes = unsafe { gcry_mpi::as_ref(value) }
        .and_then(|mpi| {
            mpi.opaque()
                .map(|opaque| opaque.as_slice().to_vec())
                .or_else(|| Mpz::from_mpi(mpi).map(|value| value.to_be()))
        })
        .unwrap_or_default();
    let Some(decoded) = decode_point(&ctx.curve, &bytes) else {
        return encoding::err(error::GPG_ERR_INV_OBJ);
    };
    if let Some(target) = point_from_raw_mut(result) {
        *target = decoded;
        0
    } else {
        encoding::err(error::GPG_ERR_INV_ARG)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_get_affine(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    point: *mut c_void,
    _ctx: *mut c_void,
) -> c_int {
    let Some(point) = point_from_raw(point) else {
        return -1;
    };
    if point.is_infinity() {
        return -1;
    }
    set_target(x, point.x.clone().unwrap_or_else(|| Mpz::from_ui(0)));
    if !y.is_null() {
        set_target(y, point.y.clone().unwrap_or_else(|| Mpz::from_ui(0)));
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_dup(w: *mut c_void, u: *mut c_void, _ctx: *mut c_void) {
    if let (Some(w), Some(u)) = (point_from_raw_mut(w), point_from_raw(u)) {
        *w = u.clone();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_add(
    w: *mut c_void,
    u: *mut c_void,
    v: *mut c_void,
    ctx: *mut c_void,
) {
    let (Some(ctx), Some(w), Some(u), Some(v)) = (
        unsafe { context::ec_ref(ctx) },
        point_from_raw_mut(w),
        point_from_raw(u),
        point_from_raw(v),
    ) else {
        return;
    };
    *w = point_add(&ctx.curve, u, v);
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_sub(
    w: *mut c_void,
    u: *mut c_void,
    v: *mut c_void,
    ctx: *mut c_void,
) {
    let (Some(ctx), Some(w), Some(u), Some(v)) = (
        unsafe { context::ec_ref(ctx) },
        point_from_raw_mut(w),
        point_from_raw(u),
        point_from_raw(v),
    ) else {
        return;
    };
    let neg_v = if v.is_infinity() {
        v.clone()
    } else if ctx.curve.kind == CurveKind::Edwards {
        EcPoint::affine(
            v.x.as_ref().unwrap().mod_neg(&ctx.curve.p),
            v.y.as_ref().unwrap().clone(),
        )
    } else {
        EcPoint::affine(
            v.x.as_ref().unwrap().clone(),
            v.y.as_ref().unwrap().mod_neg(&ctx.curve.p),
        )
    };
    *w = point_add(&ctx.curve, u, &neg_v);
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_mul(
    w: *mut c_void,
    n: *mut gcry_mpi,
    u: *mut c_void,
    ctx: *mut c_void,
) {
    let (Some(ctx), Some(w), Some(scalar), Some(point)) = (
        unsafe { context::ec_ref(ctx) },
        point_from_raw_mut(w),
        mpi_to_mpz(n),
        point_from_raw(u),
    ) else {
        return;
    };
    *w = scalar_mul_secret(&ctx.curve, &scalar, point);
}

#[unsafe(no_mangle)]
pub extern "C" fn gcry_mpi_ec_curve_point(w: *mut c_void, ctx: *mut c_void) -> c_int {
    let (Some(ctx), Some(point)) = (unsafe { context::ec_ref(ctx) }, point_from_raw(w)) else {
        return 0;
    };
    curve_point(&ctx.curve, point) as c_int
}

pub(crate) fn context_curve(ctx: &EcContext) -> &Curve {
    &ctx.curve
}

pub(crate) fn context_q(ctx: &EcContext) -> Option<&EcPoint> {
    ctx.q.as_ref()
}

pub(crate) fn context_d(ctx: &EcContext) -> Option<&Mpz> {
    ctx.d.as_ref()
}

pub(crate) fn curve_order(curve: &Curve) -> &Mpz {
    &curve.n
}

pub(crate) fn add_points(curve: &Curve, left: &EcPoint, right: &EcPoint) -> EcPoint {
    point_add(curve, left, right)
}

pub(crate) fn curve_param_bytes(curve: &Curve, name: &str) -> Option<Vec<u8>> {
    match name {
        "p" => Some(curve.p.to_be()),
        "a" => Some(curve.a.to_be()),
        "b" => Some(curve.b.to_be()),
        "g" => Some(encode_point(curve, &base_point(curve))),
        "n" => Some(curve.n.to_be()),
        "h" => Some(curve.h.to_be()),
        _ => None,
    }
}
