use std::collections::HashSet;
use std::ffi::{c_char, c_int, c_uint, c_void, CStr};
use std::ptr::null_mut;
use std::sync::{Mutex, OnceLock};

use sha2::{Digest as _, Sha512};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::error;
use crate::global;
use crate::pubkey;
use crate::sexp;

use super::{
    export_unsigned, gcry_mpi, gcry_mpi_copy, gcry_mpi_release, import_unsigned_bytes, mpz_sgn,
    MpiKind, Mpz, __gmpz_add, __gmpz_add_ui, __gmpz_cmp, __gmpz_cmp_ui, __gmpz_fdiv_q_2exp,
    __gmpz_invert, __gmpz_mod, __gmpz_mul, __gmpz_neg, __gmpz_powm, __gmpz_set_ui,
    __gmpz_sizeinbase, __gmpz_sub, __gmpz_sub_ui, __gmpz_tstbit, GCRYMPI_FMT_OPAQUE,
    GCRYMPI_FMT_USG,
};

const ECDSA_TOKEN: &[u8] = b"ecdsa\0";
const MPI_PARAM_P: &[u8] = b"p\0";
const MPI_PARAM_A: &[u8] = b"a\0";

const GPG_ERR_NO_SECKEY: u32 = 17;
const GPG_ERR_UNKNOWN_NAME: u32 = 165;
const GPG_ERR_UNKNOWN_CURVE: u32 = 188;
const GPG_ERR_BAD_CRYPT_CTX: u32 = 193;
const GPG_ERR_BROKEN_PUBKEY: u32 = 195;

const GCRY_ECC_CURVE25519: c_int = 1;
const GCRY_ECC_CURVE448: c_int = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CurveModel {
    Weierstrass,
    Montgomery,
    Edwards,
}

#[derive(Clone, Copy)]
struct CurveDef {
    canonical: &'static str,
    canonical_cstr: &'static [u8],
    nbits: c_uint,
    fips: bool,
    model: CurveModel,
    eddsa: bool,
    montgomery_prefix: bool,
    p: Option<&'static str>,
    a: Option<&'static str>,
    b: Option<&'static str>,
    n: Option<&'static str>,
    gx: Option<&'static str>,
    gy: Option<&'static str>,
    h: c_uint,
}

struct CurveAlias {
    canonical: &'static str,
    alias: &'static str,
}

#[repr(C)]
struct LocalPoint {
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
}

impl LocalPoint {
    fn boxed() -> Box<Self> {
        Box::new(Self {
            x: super::gcry_mpi_new(0),
            y: super::gcry_mpi_new(0),
            z: super::gcry_mpi_new(0),
        })
    }

    unsafe fn as_ref<'a>(ptr: *const c_void) -> Option<&'a Self> {
        unsafe { (ptr as *const Self).as_ref() }
    }

    unsafe fn as_mut<'a>(ptr: *mut c_void) -> Option<&'a mut Self> {
        unsafe { (ptr as *mut Self).as_mut() }
    }
}

impl Drop for LocalPoint {
    fn drop(&mut self) {
        gcry_mpi_release(self.x);
        gcry_mpi_release(self.y);
        gcry_mpi_release(self.z);
    }
}

struct EcContext {
    curve: Option<&'static CurveDef>,
    eddsa_secret: bool,
    p: *mut gcry_mpi,
    a: *mut gcry_mpi,
    b: *mut gcry_mpi,
    n: *mut gcry_mpi,
    h: c_uint,
    g: *mut LocalPoint,
    q: *mut LocalPoint,
    d: *mut gcry_mpi,
}

impl EcContext {
    unsafe fn as_ref<'a>(ptr: *const c_void) -> Option<&'a Self> {
        unsafe { (ptr as *const Self).as_ref() }
    }

    unsafe fn as_mut<'a>(ptr: *mut c_void) -> Option<&'a mut Self> {
        unsafe { (ptr as *mut Self).as_mut() }
    }

    fn model(&self) -> CurveModel {
        self.curve
            .map_or(CurveModel::Weierstrass, |curve| curve.model)
    }

    fn nbits(&self) -> c_uint {
        if let Some(curve) = self.curve {
            curve.nbits
        } else {
            super::gcry_mpi_get_nbits(self.p)
        }
    }
}

impl Drop for EcContext {
    fn drop(&mut self) {
        gcry_mpi_release(self.p);
        gcry_mpi_release(self.a);
        gcry_mpi_release(self.b);
        gcry_mpi_release(self.n);
        if !self.g.is_null() {
            unsafe {
                drop(Box::from_raw(self.g));
            }
        }
        if !self.q.is_null() {
            unsafe {
                drop(Box::from_raw(self.q));
            }
        }
        gcry_mpi_release(self.d);
    }
}

struct AffinePoint {
    x: Mpz,
    y: Mpz,
}

enum PointValue {
    Infinity,
    EdwardsIdentity,
    Affine(AffinePoint),
}

impl Clone for AffinePoint {
    fn clone(&self) -> Self {
        Self {
            x: Mpz::clone_from(self.x.as_ptr()),
            y: Mpz::clone_from(self.y.as_ptr()),
        }
    }
}

impl Clone for PointValue {
    fn clone(&self) -> Self {
        match self {
            Self::Infinity => Self::Infinity,
            Self::EdwardsIdentity => Self::EdwardsIdentity,
            Self::Affine(point) => Self::Affine(point.clone()),
        }
    }
}

const CURVES: &[CurveDef] = &[
    CurveDef {
        canonical: "Ed25519",
        canonical_cstr: b"Ed25519\0",
        nbits: 255,
        fips: false,
        model: CurveModel::Edwards,
        eddsa: true,
        montgomery_prefix: false,
        p: Some("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"),
        a: Some("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC"),
        b: Some("0x52036CEE2B6FFE738CC740797779E89800700A4D4141D8AB75EB4DCA135978A3"),
        n: Some("0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"),
        gx: Some("0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A"),
        gy: Some("0x6666666666666666666666666666666666666666666666666666666666666658"),
        h: 8,
    },
    CurveDef {
        canonical: "Curve25519",
        canonical_cstr: b"Curve25519\0",
        nbits: 255,
        fips: false,
        model: CurveModel::Montgomery,
        eddsa: false,
        montgomery_prefix: true,
        p: Some("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"),
        a: Some("0x01DB41"),
        b: Some("0x01"),
        n: Some("0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"),
        gx: Some("0x0000000000000000000000000000000000000000000000000000000000000009"),
        gy: Some("0x20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9"),
        h: 8,
    },
    CurveDef {
        canonical: "Ed448",
        canonical_cstr: b"Ed448\0",
        nbits: 448,
        fips: false,
        model: CurveModel::Edwards,
        eddsa: true,
        montgomery_prefix: false,
        p: Some("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        a: Some("0x01"),
        b: Some("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6756"),
        n: Some("0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3"),
        gx: Some("0x4F1970C66BED0DED221D15A622BF36DA9E146570470F1767EA6DE324A3D3A46412AE1AF72AB66511433B80E18B00938E2626A82BC70CC05E"),
        gy: Some("0x693F46716EB6BC248876203756C9C7624BEA73736CA3984087789C1E05A0C2D73AD3FF1CE67C39C4FDBD132C4ED7C8AD9808795BF230FA14"),
        h: 4,
    },
    CurveDef {
        canonical: "X448",
        canonical_cstr: b"X448\0",
        nbits: 448,
        fips: false,
        model: CurveModel::Montgomery,
        eddsa: false,
        montgomery_prefix: false,
        p: Some(
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE\
             FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ),
        a: Some("0x98A9"),
        b: Some("0x01"),
        n: Some(
            "0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\
             7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3",
        ),
        gx: Some(
            "0x0000000000000000000000000000000000000000000000000000000000000000\
             00000000000000000000000000000000000000000000000000000005",
        ),
        gy: Some(
            "0x7D235D1295F5B1F66C98AB6E58326FCECBAE5D34F55545D060F75DC2\
             8DF3F6EDB8027E2346430D211312C4B150677AF76FD7223D457B5B1A",
        ),
        h: 4,
    },
    CurveDef {
        canonical: "NIST P-192",
        canonical_cstr: b"NIST P-192\0",
        nbits: 192,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xfffffffffffffffffffffffffffffffeffffffffffffffff"),
        a: Some("0xfffffffffffffffffffffffffffffffefffffffffffffffc"),
        b: Some("0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"),
        n: Some("0xffffffffffffffffffffffff99def836146bc9b1b4d22831"),
        gx: Some("0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"),
        gy: Some("0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
        h: 1,
    },
    CurveDef {
        canonical: "NIST P-224",
        canonical_cstr: b"NIST P-224\0",
        nbits: 224,
        fips: true,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xffffffffffffffffffffffffffffffff000000000000000000000001"),
        a: Some("0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe"),
        b: Some("0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4"),
        n: Some("0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d"),
        gx: Some("0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21"),
        gy: Some("0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
        h: 1,
    },
    CurveDef {
        canonical: "NIST P-256",
        canonical_cstr: b"NIST P-256\0",
        nbits: 256,
        fips: true,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
        a: Some("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"),
        b: Some("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
        n: Some("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
        gx: Some("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        gy: Some("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        h: 1,
    },
    CurveDef {
        canonical: "NIST P-384",
        canonical_cstr: b"NIST P-384\0",
        nbits: 384,
        fips: true,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some(
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
             ffffffff0000000000000000ffffffff",
        ),
        a: Some(
            "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
             ffffffff0000000000000000fffffffc",
        ),
        b: Some(
            "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
             c656398d8a2ed19d2a85c8edd3ec2aef",
        ),
        n: Some(
            "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
             581a0db248b0a77aecec196accc52973",
        ),
        gx: Some(
            "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
             5502f25dbf55296c3a545e3872760ab7",
        ),
        gy: Some(
            "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
             0a60b1ce1d7e819d7a431d7c90ea0e5f",
        ),
        h: 1,
    },
    CurveDef {
        canonical: "NIST P-521",
        canonical_cstr: b"NIST P-521\0",
        nbits: 521,
        fips: true,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some(
            "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        a: Some(
            "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc",
        ),
        b: Some(
            "0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef10\
             9e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        ),
        n: Some(
            "0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        ),
        gx: Some(
            "0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
             3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        ),
        gy: Some(
            "0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
             662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
        ),
        h: 1,
    },
    CurveDef {
        canonical: "brainpoolP160r1",
        canonical_cstr: b"brainpoolP160r1\0",
        nbits: 160,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xe95e4a5f737059dc60dfc7ad95b3d8139515620f"),
        a: Some("0x340e7be2a280eb74e2be61bada745d97e8f7c300"),
        b: Some("0x1e589a8595423412134faa2dbdec95c8d8675e58"),
        n: Some("0xe95e4a5f737059dc60df5991d45029409e60fc09"),
        gx: Some("0xbed5af16ea3f6a4f62938c4631eb5af7bdbcdbc3"),
        gy: Some("0x1667cb477a1a8ec338f94741669c976316da6321"),
        h: 1,
    },
    CurveDef {
        canonical: "brainpoolP192r1",
        canonical_cstr: b"brainpoolP192r1\0",
        nbits: 192,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xc302f41d932a36cda7a3463093d18db78fce476de1a86297"),
        a: Some("0x6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef"),
        b: Some("0x469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9"),
        n: Some("0xc302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1"),
        gx: Some("0xc0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6"),
        gy: Some("0x14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f"),
        h: 1,
    },
    CurveDef {
        canonical: "brainpoolP224r1",
        canonical_cstr: b"brainpoolP224r1\0",
        nbits: 224,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xd7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff"),
        a: Some("0x68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43"),
        b: Some("0x2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b"),
        n: Some("0xd7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f"),
        gx: Some("0x0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d"),
        gy: Some("0x58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd"),
        h: 1,
    },
    CurveDef {
        canonical: "brainpoolP256r1",
        canonical_cstr: b"brainpoolP256r1\0",
        nbits: 256,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377"),
        a: Some("0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9"),
        b: Some("0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6"),
        n: Some("0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7"),
        gx: Some("0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262"),
        gy: Some("0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997"),
        h: 1,
    },
    CurveDef {
        canonical: "brainpoolP320r1",
        canonical_cstr: b"brainpoolP320r1\0",
        nbits: 320,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xd35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27"),
        a: Some("0x3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4"),
        b: Some("0x520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6"),
        n: Some("0xd35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311"),
        gx: Some("0x43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e20611"),
        gy: Some("0x14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1"),
        h: 1,
    },
    CurveDef {
        canonical: "brainpoolP384r1",
        canonical_cstr: b"brainpoolP384r1\0",
        nbits: 384,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53"),
        a: Some("0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826"),
        b: Some("0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11"),
        n: Some("0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565"),
        gx: Some("0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e"),
        gy: Some("0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315"),
        h: 1,
    },
    CurveDef {
        canonical: "brainpoolP512r1",
        canonical_cstr: b"brainpoolP512r1\0",
        nbits: 512,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3"),
        a: Some("0x7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca"),
        b: Some("0x3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723"),
        n: Some("0xaadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069"),
        gx: Some("0x81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822"),
        gy: Some("0x7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892"),
        h: 1,
    },
    CurveDef {
        canonical: "GOST2001-test",
        canonical_cstr: b"GOST2001-test\0",
        nbits: 256,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0x8000000000000000000000000000000000000000000000000000000000000431"),
        a: Some("0x0000000000000000000000000000000000000000000000000000000000000007"),
        b: Some("0x5fbff498aa938ce739b8e022fbafef40563f6e6a3472fc2a514c0ce9dae23b7e"),
        n: Some("0x8000000000000000000000000000000150fe8a1892976154c59cfc193accf5b3"),
        gx: Some("0x0000000000000000000000000000000000000000000000000000000000000002"),
        gy: Some("0x08e2a8a0e65147d4bd6316030e16d19c85c97f0a9ca267122b96abbcea7e8fc8"),
        h: 1,
    },
    CurveDef {
        canonical: "GOST2001-CryptoPro-A",
        canonical_cstr: b"GOST2001-CryptoPro-A\0",
        nbits: 256,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"),
        a: Some("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94"),
        b: Some("0x00000000000000000000000000000000000000000000000000000000000000a6"),
        n: Some("0xffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893"),
        gx: Some("0x0000000000000000000000000000000000000000000000000000000000000001"),
        gy: Some("0x8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14"),
        h: 1,
    },
    CurveDef {
        canonical: "GOST2001-CryptoPro-B",
        canonical_cstr: b"GOST2001-CryptoPro-B\0",
        nbits: 256,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0x8000000000000000000000000000000000000000000000000000000000000c99"),
        a: Some("0x8000000000000000000000000000000000000000000000000000000000000c96"),
        b: Some("0x3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b"),
        n: Some("0x800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f"),
        gx: Some("0x0000000000000000000000000000000000000000000000000000000000000001"),
        gy: Some("0x3fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc"),
        h: 1,
    },
    CurveDef {
        canonical: "GOST2001-CryptoPro-C",
        canonical_cstr: b"GOST2001-CryptoPro-C\0",
        nbits: 256,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b"),
        a: Some("0x9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598"),
        b: Some("0x000000000000000000000000000000000000000000000000000000000000805a"),
        n: Some("0x9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9"),
        gx: Some("0x0000000000000000000000000000000000000000000000000000000000000000"),
        gy: Some("0x41ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67"),
        h: 1,
    },
    CurveDef {
        canonical: "GOST2012-256-A",
        canonical_cstr: b"GOST2012-256-A\0",
        nbits: 256,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97"),
        a: Some("0xc2173f1513981673af4892c23035a27ce25e2013bf95aa33b22c656f277e7335"),
        b: Some("0x295f9bae7428ed9ccc20e7c359a9d41a22fccd9108e17bf7ba9337a6f8ae9513"),
        n: Some("0x400000000000000000000000000000000fd8cddfc87b6635c115af556c360c67"),
        gx: Some("0x91e38443a5e82c0d880923425712b2bb658b9196932e02c78b2582fe742daa28"),
        gy: Some("0x32879423ab1a0375895786c4bb46e9565fde0b5344766740af268adb32322e5c"),
        h: 4,
    },
    CurveDef {
        canonical: "GOST2012-512-test",
        canonical_cstr: b"GOST2012-512-test\0",
        nbits: 511,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0x4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15df1d852741af4704a0458047e80e4546d35b8336fac224dd81664bbf528be6373"),
        a: Some("0x0000000000000000000000000000000000000000000000000000000000000007"),
        b: Some("0x1cff0806a31116da29d8cfa54e57eb748bc5f377e49400fdd788b649eca1ac4361834013b2ad7322480a89ca58e0cf74bc9e540c2add6897fad0a3084f302adc"),
        n: Some("0x4531acd1fe0023c7550d267b6b2fee80922b14b2ffb90f04d4eb7c09b5d2d15da82f2d7ecb1dbac719905c5eecc423f1d86e25edbe23c595d644aaf187e6e6df"),
        gx: Some("0x24d19cc64572ee30f396bf6ebbfd7a6c5213b3b3d7057cc825f91093a68cd762fd60611262cd838dc6b60aa7eee804e28bc849977fac33b4b530f1b120248a9a"),
        gy: Some("0x2bb312a43bd2ce6e0d020613c857acddcfbf061e91e5f2c3f32447c259f39b2c83ab156d77f1496bf7eb3351e1ee4e43dc1a18b91b24640b6dbb92cb1add371e"),
        h: 1,
    },
    CurveDef {
        canonical: "GOST2012-512-tc26-A",
        canonical_cstr: b"GOST2012-512-tc26-A\0",
        nbits: 512,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"),
        a: Some("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc4"),
        b: Some("0xe8c2505dedfc86ddc1bd0b2b6667f1da34b82574761cb0e879bd081cfd0b6265ee3cb090f30d27614cb4574010da90dd862ef9d4ebee4761503190785a71c760"),
        n: Some("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff27e69532f48d89116ff22b8d4e0560609b4b38abfad2b85dcacdb1411f10b275"),
        gx: Some("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003"),
        gy: Some("0x7503cfe87a836ae3a61b8816e25450e6ce5e1c93acf1abc1778064fdcbefa921df1626be4fd036e93d75e6a50e3a41e98028fe5fc235f5b889a589cb5215f2a4"),
        h: 1,
    },
    CurveDef {
        canonical: "GOST2012-512-tc26-B",
        canonical_cstr: b"GOST2012-512-tc26-B\0",
        nbits: 512,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006f"),
        a: Some("0x8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006c"),
        b: Some("0x687d1b459dc841457e3e06cf6f5e2517b97c7d614af138bcbf85dc806c4b289f3e965d2db1416d217f8b276fad1ab69c50f78bee1fa3106efb8ccbc7c5140116"),
        n: Some("0x800000000000000000000000000000000000000000000000000000000000000149a1ec142565a545acfdb77bd9d40cfa8b996712101bea0ec6346c54374f25bd"),
        gx: Some("0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002"),
        gy: Some("0x1a8f7eda389b094c2c071e3647a8940f3c123b697578c213be6dd9e6c8ec7335dcb228fd1edf4a39152cbcaaf8c0398828041055f94ceeec7e21340780fe41bd"),
        h: 1,
    },
    CurveDef {
        canonical: "GOST2012-512-tc26-C",
        canonical_cstr: b"GOST2012-512-tc26-C\0",
        nbits: 512,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7"),
        a: Some("0xdc9203e514a721875485a529d2c722fb187bc8980eb866644de41c68e143064546e861c0e2c9edd92ade71f46fcf50ff2ad97f951fda9f2a2eb6546f39689bd3"),
        b: Some("0xb4c4ee28cebc6c2c8ac12952cf37f16ac7efb6a9f69f4b57ffda2e4f0de5ade038cbc2fff719d2c18de0284b8bfef3b52b8cc7a5f5bf0a3c8d2319a5312557e1"),
        n: Some("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed"),
        gx: Some("0xe2e31edfc23de7bdebe241ce593ef5de2295b7a9cbaef021d385f7074cea043aa27272a7ae602bf2a7b9033db9ed3610c6fb85487eae97aac5bc7928c1950148"),
        gy: Some("0xf5ce40d95b5eb899abbccff5911cb8577939804d6527378b8c108c3d2090ff9be18e2d33e3021ed2ef32d85822423b6304f726aa854bae07d0396e9a9addc40f"),
        h: 4,
    },
    CurveDef {
        canonical: "secp256k1",
        canonical_cstr: b"secp256k1\0",
        nbits: 256,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
        a: Some("0x0000000000000000000000000000000000000000000000000000000000000000"),
        b: Some("0x0000000000000000000000000000000000000000000000000000000000000007"),
        n: Some("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
        gx: Some("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        gy: Some("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
        h: 1,
    },
    CurveDef {
        canonical: "sm2p256v1",
        canonical_cstr: b"sm2p256v1\0",
        nbits: 256,
        fips: false,
        model: CurveModel::Weierstrass,
        eddsa: false,
        montgomery_prefix: false,
        p: Some("0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"),
        a: Some("0xfffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc"),
        b: Some("0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93"),
        n: Some("0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"),
        gx: Some("0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"),
        gy: Some("0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"),
        h: 1,
    },
];

const CURVE_ALIASES: &[CurveAlias] = &[
    CurveAlias {
        canonical: "Ed25519",
        alias: "1.3.6.1.4.1.11591.15.1",
    },
    CurveAlias {
        canonical: "Ed25519",
        alias: "1.3.101.112",
    },
    CurveAlias {
        canonical: "Curve25519",
        alias: "1.3.6.1.4.1.3029.1.5.1",
    },
    CurveAlias {
        canonical: "Curve25519",
        alias: "1.3.101.110",
    },
    CurveAlias {
        canonical: "Curve25519",
        alias: "X25519",
    },
    CurveAlias {
        canonical: "Ed448",
        alias: "1.3.101.113",
    },
    CurveAlias {
        canonical: "X448",
        alias: "1.3.101.111",
    },
    CurveAlias {
        canonical: "NIST P-192",
        alias: "1.2.840.10045.3.1.1",
    },
    CurveAlias {
        canonical: "NIST P-192",
        alias: "prime192v1",
    },
    CurveAlias {
        canonical: "NIST P-192",
        alias: "secp192r1",
    },
    CurveAlias {
        canonical: "NIST P-192",
        alias: "nistp192",
    },
    CurveAlias {
        canonical: "NIST P-224",
        alias: "secp224r1",
    },
    CurveAlias {
        canonical: "NIST P-224",
        alias: "1.3.132.0.33",
    },
    CurveAlias {
        canonical: "NIST P-224",
        alias: "nistp224",
    },
    CurveAlias {
        canonical: "NIST P-256",
        alias: "1.2.840.10045.3.1.7",
    },
    CurveAlias {
        canonical: "NIST P-256",
        alias: "prime256v1",
    },
    CurveAlias {
        canonical: "NIST P-256",
        alias: "secp256r1",
    },
    CurveAlias {
        canonical: "NIST P-256",
        alias: "nistp256",
    },
    CurveAlias {
        canonical: "NIST P-384",
        alias: "secp384r1",
    },
    CurveAlias {
        canonical: "NIST P-384",
        alias: "1.3.132.0.34",
    },
    CurveAlias {
        canonical: "NIST P-384",
        alias: "nistp384",
    },
    CurveAlias {
        canonical: "NIST P-521",
        alias: "secp521r1",
    },
    CurveAlias {
        canonical: "NIST P-521",
        alias: "1.3.132.0.35",
    },
    CurveAlias {
        canonical: "NIST P-521",
        alias: "nistp521",
    },
    CurveAlias {
        canonical: "brainpoolP160r1",
        alias: "1.3.36.3.3.2.8.1.1.1",
    },
    CurveAlias {
        canonical: "brainpoolP192r1",
        alias: "1.3.36.3.3.2.8.1.1.3",
    },
    CurveAlias {
        canonical: "brainpoolP224r1",
        alias: "1.3.36.3.3.2.8.1.1.5",
    },
    CurveAlias {
        canonical: "brainpoolP256r1",
        alias: "1.3.36.3.3.2.8.1.1.7",
    },
    CurveAlias {
        canonical: "brainpoolP320r1",
        alias: "1.3.36.3.3.2.8.1.1.9",
    },
    CurveAlias {
        canonical: "brainpoolP384r1",
        alias: "1.3.36.3.3.2.8.1.1.11",
    },
    CurveAlias {
        canonical: "brainpoolP512r1",
        alias: "1.3.36.3.3.2.8.1.1.13",
    },
    CurveAlias {
        canonical: "GOST2001-test",
        alias: "1.2.643.2.2.35.0",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-A",
        alias: "1.2.643.2.2.35.1",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-B",
        alias: "1.2.643.2.2.35.2",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-C",
        alias: "1.2.643.2.2.35.3",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-A",
        alias: "GOST2001-CryptoPro-XchA",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-C",
        alias: "GOST2001-CryptoPro-XchB",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-A",
        alias: "1.2.643.2.2.36.0",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-C",
        alias: "1.2.643.2.2.36.1",
    },
    CurveAlias {
        canonical: "GOST2012-256-A",
        alias: "1.2.643.7.1.2.1.1.1",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-A",
        alias: "1.2.643.7.1.2.1.1.2",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-A",
        alias: "GOST2012-256-tc26-B",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-B",
        alias: "1.2.643.7.1.2.1.1.3",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-B",
        alias: "GOST2012-256-tc26-C",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-C",
        alias: "1.2.643.7.1.2.1.1.4",
    },
    CurveAlias {
        canonical: "GOST2001-CryptoPro-C",
        alias: "GOST2012-256-tc26-D",
    },
    CurveAlias {
        canonical: "GOST2012-512-test",
        alias: "GOST2012-test",
    },
    CurveAlias {
        canonical: "GOST2012-512-test",
        alias: "1.2.643.7.1.2.1.2.0",
    },
    CurveAlias {
        canonical: "GOST2012-512-tc26-A",
        alias: "GOST2012-tc26-A",
    },
    CurveAlias {
        canonical: "GOST2012-512-tc26-B",
        alias: "GOST2012-tc26-B",
    },
    CurveAlias {
        canonical: "GOST2012-512-tc26-A",
        alias: "1.2.643.7.1.2.1.2.1",
    },
    CurveAlias {
        canonical: "GOST2012-512-tc26-B",
        alias: "1.2.643.7.1.2.1.2.2",
    },
    CurveAlias {
        canonical: "GOST2012-512-tc26-C",
        alias: "1.2.643.7.1.2.1.2.3",
    },
    CurveAlias {
        canonical: "secp256k1",
        alias: "1.3.132.0.10",
    },
    CurveAlias {
        canonical: "sm2p256v1",
        alias: "1.2.156.10197.1.301",
    },
];

fn context_registry() -> &'static Mutex<HashSet<usize>> {
    static REGISTRY: OnceLock<Mutex<HashSet<usize>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashSet::new()))
}

fn lock_registry() -> std::sync::MutexGuard<'static, HashSet<usize>> {
    match context_registry().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn curve_allowed(curve: &CurveDef) -> bool {
    !global::lock_runtime_state().fips_mode || curve.fips
}

fn zero_target(target: *mut gcry_mpi) {
    if !target.is_null() {
        super::gcry_mpi_set_ui(target, 0);
    }
}

fn mpi_secure(ptr: *mut gcry_mpi) -> bool {
    unsafe { gcry_mpi::as_ref(ptr) }.is_some_and(|mpi| mpi.secure)
}

fn point_secure(point: &LocalPoint) -> bool {
    mpi_secure(point.x) || mpi_secure(point.y) || mpi_secure(point.z)
}

fn replace_mpi(slot: &mut *mut gcry_mpi, new_value: *mut gcry_mpi) {
    if *slot != new_value {
        gcry_mpi_release(*slot);
    }
    *slot = new_value;
}

fn reset_coord(slot: *mut gcry_mpi) {
    if !slot.is_null() {
        super::gcry_mpi_set_ui(slot, 0);
    }
}

fn ensure_point(point: *mut c_void) -> *mut LocalPoint {
    if point.is_null() {
        Box::into_raw(LocalPoint::boxed())
    } else {
        point.cast()
    }
}

fn cloned_point(point: *mut c_void) -> *mut c_void {
    let Some(src) = (unsafe { LocalPoint::as_ref(point) }) else {
        return null_mut();
    };
    let copy = LocalPoint {
        x: gcry_mpi_copy(src.x),
        y: gcry_mpi_copy(src.y),
        z: gcry_mpi_copy(src.z),
    };
    Box::into_raw(Box::new(copy)).cast()
}

fn ascii_case_eq(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn curve_by_canonical(name: &str) -> Option<&'static CurveDef> {
    CURVES
        .iter()
        .find(|curve| ascii_case_eq(curve.canonical, name))
}

fn curve_by_name(name: &str) -> Option<&'static CurveDef> {
    if let Some(curve) = curve_by_canonical(name) {
        return Some(curve);
    }
    let alias = CURVE_ALIASES
        .iter()
        .find(|alias| ascii_case_eq(alias.alias, name))?;
    curve_by_canonical(alias.canonical)
}

fn curve_by_index(iterator: c_int) -> Option<&'static CurveDef> {
    if iterator < 0 {
        return None;
    }
    CURVES
        .iter()
        .filter(|curve| curve_allowed(curve))
        .nth(iterator as usize)
}

fn curve_by_genkey_nbits(nbits: c_uint) -> Option<&'static CurveDef> {
    CURVES
        .iter()
        .find(|curve| curve.nbits == nbits && curve.model == CurveModel::Weierstrass)
}

pub(crate) fn genkey_curve_name_for_nbits(nbits: c_uint) -> Result<&'static str, u32> {
    let Some(curve) = curve_by_genkey_nbits(nbits) else {
        return Err(error::gcry_error_from_code(GPG_ERR_UNKNOWN_CURVE));
    };
    if !curve_allowed(curve) {
        return Err(error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED));
    }
    Ok(curve.canonical)
}

fn hex_bytes(text: &str) -> Option<(Vec<u8>, bool)> {
    let mut value = text.trim();
    let mut negative = false;
    if let Some(stripped) = value.strip_prefix('-') {
        negative = true;
        value = stripped;
    }
    if let Some(stripped) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        value = stripped;
    }
    if value.is_empty() {
        return Some((Vec::new(), negative));
    }

    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len().div_ceil(2));
    let mut idx = 0usize;
    if bytes.len() % 2 == 1 {
        out.push(nibble(bytes[0])?);
        idx = 1;
    }
    while idx < bytes.len() {
        out.push((nibble(bytes[idx])? << 4) | nibble(bytes[idx + 1])?);
        idx += 2;
    }
    while out.len() > 1 && out[0] == 0 {
        out.remove(0);
    }
    Some((out, negative))
}

fn mpz_from_hex(text: &str) -> Option<Mpz> {
    let (bytes, negative) = hex_bytes(text)?;
    let mut value = import_unsigned_bytes(&bytes);
    if negative {
        unsafe {
            __gmpz_neg(value.as_mut_ptr(), value.as_ptr());
        }
    }
    Some(value)
}

fn mpz_from_mpi(ptr: *mut gcry_mpi) -> Option<Mpz> {
    let mpi = unsafe { gcry_mpi::as_ref(ptr) }?;
    match &mpi.kind {
        MpiKind::Numeric(value) => Some(Mpz::clone_from(value.as_ptr())),
        MpiKind::Opaque(_) => None,
    }
}

fn mpz_to_mpi(value: Mpz, secure: bool) -> *mut gcry_mpi {
    gcry_mpi::from_numeric(value, secure)
}

fn assign_target_mpi(target: *mut gcry_mpi, value: Mpz, secure: bool) {
    if target.is_null() {
        return;
    }

    let tmp = mpz_to_mpi(value, secure);
    if tmp.is_null() {
        return;
    }
    super::gcry_mpi_set(target, tmp);
    gcry_mpi_release(tmp);
}

fn mpz_to_fixed_be(value: &Mpz, nbytes: usize) -> Vec<u8> {
    let mut out = export_unsigned(value.as_ptr());
    if out.len() < nbytes {
        let mut padded = vec![0u8; nbytes - out.len()];
        padded.extend_from_slice(&out);
        out = padded;
    }
    if out.len() > nbytes {
        out = out[out.len() - nbytes..].to_vec();
    }
    out
}

fn mpz_from_le(bytes: &[u8]) -> Mpz {
    let mut reversed = bytes.to_vec();
    reversed.reverse();
    import_unsigned_bytes(&reversed)
}

fn mpz_to_le_fixed(value: &Mpz, nbytes: usize) -> Vec<u8> {
    let mut out = mpz_to_fixed_be(value, nbytes);
    out.reverse();
    out
}

fn mpz_is_zero(value: &Mpz) -> bool {
    unsafe { mpz_sgn(value.as_ptr()) == 0 }
}

fn mpz_is_odd(value: &Mpz) -> bool {
    unsafe { __gmpz_tstbit(value.as_ptr(), 0) != 0 }
}

fn add_mod(left: &Mpz, right: &Mpz, modu: &Mpz) -> Mpz {
    let mut out = Mpz::new(0);
    unsafe {
        __gmpz_add(out.as_mut_ptr(), left.as_ptr(), right.as_ptr());
        __gmpz_mod(out.as_mut_ptr(), out.as_ptr(), modu.as_ptr());
    }
    out
}

fn sub_mod(left: &Mpz, right: &Mpz, modu: &Mpz) -> Mpz {
    let mut out = Mpz::new(0);
    unsafe {
        __gmpz_sub(out.as_mut_ptr(), left.as_ptr(), right.as_ptr());
        __gmpz_mod(out.as_mut_ptr(), out.as_ptr(), modu.as_ptr());
    }
    out
}

fn neg_mod(value: &Mpz, modu: &Mpz) -> Mpz {
    let zero = Mpz::from_ui(0);
    sub_mod(&zero, value, modu)
}

fn mul_mod(left: &Mpz, right: &Mpz, modu: &Mpz) -> Mpz {
    let mut out = Mpz::new(0);
    unsafe {
        __gmpz_mul(out.as_mut_ptr(), left.as_ptr(), right.as_ptr());
        __gmpz_mod(out.as_mut_ptr(), out.as_ptr(), modu.as_ptr());
    }
    out
}

fn square_mod(value: &Mpz, modu: &Mpz) -> Mpz {
    mul_mod(value, value, modu)
}

fn pow_mod(base: &Mpz, exponent: &Mpz, modu: &Mpz) -> Mpz {
    let mut out = Mpz::new(0);
    unsafe {
        __gmpz_powm(
            out.as_mut_ptr(),
            base.as_ptr(),
            exponent.as_ptr(),
            modu.as_ptr(),
        );
    }
    out
}

fn sqrt_mod_prime(value: &Mpz, modu: &Mpz) -> Option<Mpz> {
    if mpz_is_zero(value) {
        return Some(Mpz::from_ui(0));
    }

    let mut legendre_exp = Mpz::new(0);
    unsafe {
        __gmpz_sub_ui(legendre_exp.as_mut_ptr(), modu.as_ptr(), 1);
        __gmpz_fdiv_q_2exp(legendre_exp.as_mut_ptr(), legendre_exp.as_ptr(), 1);
    }
    let legendre = pow_mod(value, &legendre_exp, modu);
    if unsafe { __gmpz_cmp_ui(legendre.as_ptr(), 1) } != 0 {
        return None;
    }

    if unsafe { __gmpz_tstbit(modu.as_ptr(), 1) } != 0 {
        let mut exp = Mpz::new(0);
        unsafe {
            __gmpz_add_ui(exp.as_mut_ptr(), modu.as_ptr(), 1);
            __gmpz_fdiv_q_2exp(exp.as_mut_ptr(), exp.as_ptr(), 2);
        }
        return Some(pow_mod(value, &exp, modu));
    }

    let mut q = Mpz::new(0);
    unsafe {
        __gmpz_sub_ui(q.as_mut_ptr(), modu.as_ptr(), 1);
    }
    let mut s = 0usize;
    while unsafe { __gmpz_tstbit(q.as_ptr(), 0) } == 0 {
        unsafe {
            __gmpz_fdiv_q_2exp(q.as_mut_ptr(), q.as_ptr(), 1);
        }
        s += 1;
    }

    let mut z = Mpz::from_ui(2);
    loop {
        let non_residue = pow_mod(&z, &legendre_exp, modu);
        if unsafe { __gmpz_cmp(non_residue.as_ptr(), legendre.as_ptr()) } == 0 {
            unsafe {
                __gmpz_add_ui(z.as_mut_ptr(), z.as_ptr(), 1);
            }
            continue;
        }
        if unsafe { __gmpz_cmp_ui(non_residue.as_ptr(), 0) } == 0 {
            return None;
        }
        break;
    }

    let mut exp = Mpz::clone_from(q.as_ptr());
    unsafe {
        __gmpz_add_ui(exp.as_mut_ptr(), exp.as_ptr(), 1);
        __gmpz_fdiv_q_2exp(exp.as_mut_ptr(), exp.as_ptr(), 1);
    }
    let mut m = s;
    let mut c = pow_mod(&z, &q, modu);
    let mut t = pow_mod(value, &q, modu);
    let mut x = pow_mod(value, &exp, modu);

    while unsafe { __gmpz_cmp_ui(t.as_ptr(), 1) } != 0 {
        let mut i = 1usize;
        let mut t2 = square_mod(&t, modu);
        while i < m && unsafe { __gmpz_cmp_ui(t2.as_ptr(), 1) } != 0 {
            t2 = square_mod(&t2, modu);
            i += 1;
        }
        if i == m {
            return None;
        }

        let mut b_exp = Mpz::from_ui(1);
        if m > i + 1 {
            b_exp = Mpz::from_ui((1usize << (m - i - 1)) as _);
        }
        let b = pow_mod(&c, &b_exp, modu);
        let b2 = square_mod(&b, modu);
        x = mul_mod(&x, &b, modu);
        t = mul_mod(&t, &b2, modu);
        c = b2;
        m = i;
    }

    Some(x)
}

fn inv_mod(value: &Mpz, modu: &Mpz) -> Option<Mpz> {
    let mut out = Mpz::new(0);
    let ok = unsafe { __gmpz_invert(out.as_mut_ptr(), value.as_ptr(), modu.as_ptr()) } != 0;
    ok.then_some(out)
}

fn mod_eq(left: &Mpz, right: &Mpz, modu: &Mpz) -> bool {
    let left = sub_mod(left, &Mpz::from_ui(0), modu);
    let right = sub_mod(right, &Mpz::from_ui(0), modu);
    unsafe { __gmpz_cmp(left.as_ptr(), right.as_ptr()) == 0 }
}

fn bytes_for_bits(nbits: c_uint) -> usize {
    (nbits as usize).div_ceil(8)
}

fn eddsa_encoding_bytes(nbits: c_uint) -> usize {
    if nbits % 8 == 0 {
        (nbits as usize / 8) + 1
    } else {
        bytes_for_bits(nbits)
    }
}

fn point_coordinate_bytes(ctx: &EcContext) -> usize {
    if ctx.curve.is_some_and(|curve| curve.eddsa) {
        eddsa_encoding_bytes(ctx.nbits())
    } else {
        bytes_for_bits(ctx.nbits())
    }
}

fn point_value_from_handle(point: &LocalPoint, ctx: &EcContext) -> Option<PointValue> {
    let z = mpz_from_mpi(point.z)?;
    match ctx.model() {
        CurveModel::Edwards => {
            if unsafe { __gmpz_cmp(z.as_ptr(), Mpz::from_ui(1).as_ptr()) } != 0 {
                return None;
            }
            let x = mpz_from_mpi(point.x)?;
            let y = mpz_from_mpi(point.y)?;
            if mpz_is_zero(&x) && unsafe { __gmpz_cmp_ui(y.as_ptr(), 1) == 0 } {
                Some(PointValue::EdwardsIdentity)
            } else {
                Some(PointValue::Affine(AffinePoint { x, y }))
            }
        }
        CurveModel::Weierstrass => {
            if mpz_is_zero(&z) {
                return Some(PointValue::Infinity);
            }
            if unsafe { __gmpz_cmp(z.as_ptr(), Mpz::from_ui(1).as_ptr()) } != 0 {
                return None;
            }
            Some(PointValue::Affine(AffinePoint {
                x: mpz_from_mpi(point.x)?,
                y: mpz_from_mpi(point.y)?,
            }))
        }
        CurveModel::Montgomery => {
            if mpz_is_zero(&z) {
                return Some(PointValue::Infinity);
            }
            if unsafe { __gmpz_cmp(z.as_ptr(), Mpz::from_ui(1).as_ptr()) } != 0 {
                return None;
            }
            Some(PointValue::Affine(AffinePoint {
                x: mpz_from_mpi(point.x)?,
                y: Mpz::from_ui(0),
            }))
        }
    }
}

fn write_point_value(point: &mut LocalPoint, value: PointValue, secure: bool) {
    match value {
        PointValue::Infinity => {
            super::gcry_mpi_set_ui(point.x, 0);
            super::gcry_mpi_set_ui(point.y, 0);
            super::gcry_mpi_set_ui(point.z, 0);
        }
        PointValue::EdwardsIdentity => {
            super::gcry_mpi_set_ui(point.x, 0);
            super::gcry_mpi_set_ui(point.y, 1);
            super::gcry_mpi_set_ui(point.z, 1);
        }
        PointValue::Affine(affine) => {
            replace_mpi(&mut point.x, mpz_to_mpi(affine.x, secure));
            replace_mpi(&mut point.y, mpz_to_mpi(affine.y, secure));
            super::gcry_mpi_set_ui(point.z, 1);
        }
    }
}

fn curve_param(field: Option<&'static str>) -> Option<*mut gcry_mpi> {
    Some(mpz_to_mpi(mpz_from_hex(field?)?, false))
}

fn point_from_curve(def: &CurveDef) -> Option<*mut LocalPoint> {
    let mut point = LocalPoint::boxed();
    replace_mpi(&mut point.x, curve_param(def.gx)?);
    replace_mpi(&mut point.y, curve_param(def.gy)?);
    super::gcry_mpi_set_ui(point.z, 1);
    Some(Box::into_raw(point))
}

fn h_to_mpi(h: c_uint) -> *mut gcry_mpi {
    let mut mpi = Mpz::from_ui(h as _);
    if h == 0 {
        unsafe {
            __gmpz_set_ui(mpi.as_mut_ptr(), 0);
        }
    }
    mpz_to_mpi(mpi, false)
}

fn context_from_curve(curve: &'static CurveDef) -> Option<EcContext> {
    Some(EcContext {
        curve: Some(curve),
        eddsa_secret: false,
        p: curve_param(curve.p)?,
        a: curve_param(curve.a)?,
        b: curve_param(curve.b)?,
        n: curve_param(curve.n)?,
        h: curve.h,
        g: point_from_curve(curve)?,
        q: null_mut(),
        d: null_mut(),
    })
}

fn mpi_eq_hex(ptr: *mut gcry_mpi, expected: &'static str) -> bool {
    let Some(expected) = mpz_from_hex(expected) else {
        return false;
    };
    let Some(actual) = mpz_from_mpi(ptr) else {
        return false;
    };
    unsafe { __gmpz_cmp(actual.as_ptr(), expected.as_ptr()) == 0 }
}

fn curve_matches_params(key: *mut sexp::gcry_sexp) -> Option<&'static CurveDef> {
    let p = pubkey::token_mpi(key, b"p\0", GCRYMPI_FMT_USG);
    let a = pubkey::token_mpi(key, b"a\0", GCRYMPI_FMT_USG);
    let b = pubkey::token_mpi(key, b"b\0", GCRYMPI_FMT_USG);
    let n = pubkey::token_mpi(key, b"n\0", GCRYMPI_FMT_USG);
    let h = pubkey::token_mpi(key, b"h\0", GCRYMPI_FMT_USG);
    if p.is_null() || a.is_null() || b.is_null() || n.is_null() || h.is_null() {
        return None;
    }

    CURVES.iter().find(|curve| {
        curve.p.zip(curve.a).zip(curve.b).zip(curve.n).is_some()
            && mpi_eq_hex(p.raw(), curve.p.unwrap())
            && mpi_eq_hex(a.raw(), curve.a.unwrap())
            && mpi_eq_hex(b.raw(), curve.b.unwrap())
            && mpi_eq_hex(n.raw(), curve.n.unwrap())
            && h.as_ref()
                .and_then(|value| match &value.kind {
                    MpiKind::Numeric(number) => Some(number),
                    MpiKind::Opaque(_) => None,
                })
                .is_some_and(|number| unsafe {
                    __gmpz_cmp(number.as_ptr(), Mpz::from_ui(curve.h as _).as_ptr()) == 0
                })
    })
}

fn legacy_ecdsa_param_error(keyparam: *mut sexp::gcry_sexp, curvename: *const c_char) -> bool {
    if keyparam.is_null() || !curvename.is_null() {
        return false;
    }
    if pubkey::token_present(keyparam, b"curve\0") {
        return false;
    }

    let ecdsa = sexp::gcry_sexp_find_token(keyparam, ECDSA_TOKEN.as_ptr().cast(), 0);
    if ecdsa.is_null() {
        return false;
    }

    let has_p = !sexp::gcry_sexp_find_token(ecdsa, MPI_PARAM_P.as_ptr().cast(), 0).is_null();
    let has_a = !sexp::gcry_sexp_find_token(ecdsa, MPI_PARAM_A.as_ptr().cast(), 0).is_null();
    sexp::gcry_sexp_release(ecdsa);
    !(has_p && has_a)
}

fn parse_custom_context(keyparam: *mut sexp::gcry_sexp) -> Option<EcContext> {
    let p = pubkey::token_mpi(keyparam, b"p\0", GCRYMPI_FMT_USG).into_raw();
    let a = pubkey::token_mpi(keyparam, b"a\0", GCRYMPI_FMT_USG).into_raw();
    if p.is_null() || a.is_null() {
        gcry_mpi_release(p);
        gcry_mpi_release(a);
        return None;
    }

    let b = pubkey::token_mpi(keyparam, b"b\0", GCRYMPI_FMT_USG).into_raw();
    let n = pubkey::token_mpi(keyparam, b"n\0", GCRYMPI_FMT_USG).into_raw();
    let h = pubkey::token_mpi(keyparam, b"h\0", GCRYMPI_FMT_USG);
    let mut h_value = 1u32;
    if !h.is_null() {
        let _ = super::gcry_mpi_get_ui(&mut h_value, h.raw());
    }

    let g_point = if pubkey::token_present(keyparam, b"g\0")
        || pubkey::token_present(keyparam, b"g.x\0")
        || pubkey::token_present(keyparam, b"g.y\0")
    {
        point_from_keyparam(keyparam, "g", None).ok()
    } else {
        None
    };

    Some(EcContext {
        curve: None,
        eddsa_secret: false,
        p,
        a,
        b,
        n,
        h: h_value,
        g: g_point.unwrap_or(null_mut()),
        q: null_mut(),
        d: null_mut(),
    })
}

fn recover_weierstrass_point(ctx: &EcContext, x: Mpz, odd: bool) -> Option<AffinePoint> {
    let p = mpz_from_mpi(ctx.p)?;
    let a = mpz_from_mpi(ctx.a)?;
    let b = mpz_from_mpi(ctx.b)?;
    if unsafe { __gmpz_cmp(x.as_ptr(), p.as_ptr()) } >= 0 {
        return None;
    }

    let x2 = square_mod(&x, &p);
    let x3 = mul_mod(&x2, &x, &p);
    let ax = mul_mod(&a, &x, &p);
    let rhs = add_mod(&add_mod(&x3, &ax, &p), &b, &p);
    let mut y = sqrt_mod_prime(&rhs, &p)?;
    if mpz_is_odd(&y) != odd {
        y = sub_mod(&p, &y, &p);
    }
    Some(AffinePoint { x, y })
}

fn decode_sec1_point(ctx: &EcContext, bytes: &[u8], nbytes: usize) -> Option<AffinePoint> {
    if bytes.len() == nbytes + 1 && matches!(bytes.first(), Some(0x02 | 0x03)) {
        let x = import_unsigned_bytes(&bytes[1..]);
        return recover_weierstrass_point(ctx, x, bytes[0] == 0x03);
    }

    let body = if bytes.len() == 1 + 2 * nbytes && bytes.first() == Some(&0x04) {
        &bytes[1..]
    } else if bytes.len() == 2 * nbytes {
        bytes
    } else if bytes.len() == 1 + 2 * nbytes + 1 && bytes.first() == Some(&0x00) {
        &bytes[2..]
    } else {
        return None;
    };
    Some(AffinePoint {
        x: import_unsigned_bytes(&body[..nbytes]),
        y: import_unsigned_bytes(&body[nbytes..]),
    })
}

fn montgomery_input_x(ctx: &EcContext, bytes: &[u8], nbytes: usize) -> Option<Mpz> {
    let bytes = if bytes.len() == nbytes + 1 && matches!(bytes.first(), Some(0x00 | 0x40)) {
        &bytes[1..]
    } else if bytes.len() > nbytes {
        return None;
    } else {
        bytes
    };

    let mut buf = bytes.to_vec();
    while buf.len() < nbytes {
        buf.push(0);
    }
    if nbytes == 0 {
        return None;
    }
    if ctx
        .curve
        .is_some_and(|curve| curve.canonical == "Curve25519")
    {
        if let Some(last) = buf.last_mut() {
            *last &= 0x7f;
        }
    }
    Some(mpz_from_le(&buf))
}

fn ed25519_curve() -> &'static CurveDef {
    curve_by_canonical("Ed25519").expect("ed25519 curve present")
}

fn ed25519_i_constant() -> Mpz {
    let p = mpz_from_hex(ed25519_curve().p.expect("ed25519 p")).expect("ed25519 p valid");
    let mut exp = Mpz::new(0);
    unsafe {
        __gmpz_sub(exp.as_mut_ptr(), p.as_ptr(), Mpz::from_ui(1).as_ptr());
        __gmpz_fdiv_q_2exp(exp.as_mut_ptr(), exp.as_ptr(), 2);
    }
    pow_mod(&Mpz::from_ui(2), &exp, &p)
}

fn ed25519_sqrt_ratio(u: &Mpz, v: &Mpz, p: &Mpz) -> Option<Mpz> {
    let v2 = square_mod(v, p);
    let v3 = mul_mod(&v2, v, p);
    let v7 = mul_mod(&square_mod(&v3, p), v, p);
    let uv3 = mul_mod(u, &v3, p);
    let uv7 = mul_mod(u, &v7, p);

    let mut exp = Mpz::new(0);
    unsafe {
        __gmpz_sub(exp.as_mut_ptr(), p.as_ptr(), Mpz::from_ui(5).as_ptr());
        __gmpz_fdiv_q_2exp(exp.as_mut_ptr(), exp.as_ptr(), 3);
    }

    let x = mul_mod(&uv3, &pow_mod(&uv7, &exp, p), p);
    let vx2 = mul_mod(v, &square_mod(&x, p), p);
    if mod_eq(&vx2, u, p) {
        return Some(x);
    }

    let i = ed25519_i_constant();
    let x_alt = mul_mod(&x, &i, p);
    let vx2_alt = mul_mod(v, &square_mod(&x_alt, p), p);
    mod_eq(&vx2_alt, u, p).then_some(x_alt)
}

fn recover_ed25519_x(y: &Mpz, sign: u8) -> Option<Mpz> {
    let curve = ed25519_curve();
    let p = mpz_from_hex(curve.p.expect("ed25519 p")).expect("ed25519 p");
    if unsafe { __gmpz_cmp(y.as_ptr(), p.as_ptr()) } >= 0 {
        return None;
    }
    let d = mpz_from_hex(curve.b.expect("ed25519 d")).expect("ed25519 d");

    let y2 = square_mod(&y, &p);
    let numerator = sub_mod(&y2, &Mpz::from_ui(1), &p);
    let denominator = add_mod(&mul_mod(&d, &y2, &p), &Mpz::from_ui(1), &p);
    let mut x = ed25519_sqrt_ratio(&numerator, &denominator, &p)?;
    if (mpz_is_odd(&x) as u8) != sign {
        x = sub_mod(&p, &x, &p);
    }
    Some(x)
}

fn recover_ed448_x(y: &Mpz, sign: u8, ctx: &EcContext) -> Option<Mpz> {
    let p = mpz_from_mpi(ctx.p)?;
    if unsafe { __gmpz_cmp(y.as_ptr(), p.as_ptr()) } >= 0 {
        return None;
    }
    let d = mpz_from_mpi(ctx.b)?;
    let y2 = square_mod(y, &p);
    let u = sub_mod(&y2, &Mpz::from_ui(1), &p);
    let v = sub_mod(&mul_mod(&d, &y2, &p), &Mpz::from_ui(1), &p);
    let u3 = pow_mod(&u, &Mpz::from_ui(3), &p);
    let v3 = pow_mod(&v, &Mpz::from_ui(3), &p);
    let u5 = pow_mod(&u, &Mpz::from_ui(5), &p);

    let mut exp = Mpz::new(0);
    unsafe {
        __gmpz_sub(exp.as_mut_ptr(), p.as_ptr(), Mpz::from_ui(3).as_ptr());
        __gmpz_fdiv_q_2exp(exp.as_mut_ptr(), exp.as_ptr(), 2);
    }

    let t = pow_mod(&mul_mod(&u5, &v3, &p), &exp, &p);
    let mut x = mul_mod(&mul_mod(&t, &u3, &p), &v, &p);
    let check = mul_mod(&mul_mod(&x, &x, &p), &v, &p);
    if !mod_eq(&check, &u, &p) {
        return None;
    }
    if mpz_is_zero(&x) && sign != 0 {
        return None;
    }
    if (mpz_is_odd(&x) as u8) != sign {
        x = sub_mod(&p, &x, &p);
    }
    Some(x)
}

fn decode_eddsa_point(ctx: &EcContext, bytes: &[u8]) -> Option<AffinePoint> {
    let len = eddsa_encoding_bytes(ctx.nbits());
    if bytes.len() == (2 * len) + 1 && bytes.first() == Some(&0x04) {
        let body = &bytes[1..];
        return Some(AffinePoint {
            x: import_unsigned_bytes(&body[..len]),
            y: import_unsigned_bytes(&body[len..]),
        });
    }

    let raw = if bytes.len() == len {
        bytes
    } else if bytes.len() == len + 1 && bytes.first() == Some(&0x40) {
        &bytes[1..]
    } else {
        return None;
    };

    let sign = raw[len - 1] >> 7;
    let mut y_bytes = raw.to_vec();
    y_bytes[len - 1] &= 0x7f;
    let y = mpz_from_le(&y_bytes);
    let x = match ctx.curve.map(|curve| curve.canonical) {
        Some("Ed25519") => recover_ed25519_x(&y, sign)?,
        Some("Ed448") => recover_ed448_x(&y, sign, ctx)?,
        _ => return None,
    };
    Some(AffinePoint { x, y })
}

fn decode_point_bytes(ctx: &EcContext, bytes: &[u8]) -> Option<PointValue> {
    match ctx.model() {
        CurveModel::Weierstrass => {
            let nbytes = bytes_for_bits(ctx.nbits());
            decode_sec1_point(ctx, bytes, nbytes).map(PointValue::Affine)
        }
        CurveModel::Edwards => decode_eddsa_point(ctx, bytes).map(|point| {
            if mpz_is_zero(&point.x) && unsafe { __gmpz_cmp_ui(point.y.as_ptr(), 1) == 0 } {
                PointValue::EdwardsIdentity
            } else {
                PointValue::Affine(point)
            }
        }),
        CurveModel::Montgomery => {
            montgomery_input_x(ctx, bytes, bytes_for_bits(ctx.nbits())).map(|x| {
                PointValue::Affine(AffinePoint {
                    x,
                    y: Mpz::from_ui(0),
                })
            })
        }
    }
}

fn point_from_keyparam(
    keyparam: *mut sexp::gcry_sexp,
    name: &str,
    ctx: Option<&EcContext>,
) -> Result<*mut LocalPoint, u32> {
    let name_c = std::ffi::CString::new(name).expect("name");
    let list = sexp::gcry_sexp_find_token(keyparam, name_c.as_ptr(), 0);
    if !list.is_null() {
        let encoded = sexp::gcry_sexp_nth_mpi(list, 1, GCRYMPI_FMT_OPAQUE);
        sexp::gcry_sexp_release(list);
        if encoded.is_null() {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
        }
        let bytes = pubkey::mpi_to_bytes(encoded);
        gcry_mpi_release(encoded);
        let Some(ctx) = ctx else {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
        };
        let Some(decoded) = bytes.and_then(|bytes| decode_point_bytes(ctx, &bytes)) else {
            return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
        };
        let mut point = LocalPoint::boxed();
        write_point_value(&mut point, decoded, false);
        return Ok(Box::into_raw(point));
    }

    let mut x_name = String::from(name);
    x_name.push_str(".x");
    let mut y_name = String::from(name);
    y_name.push_str(".y");
    let mut z_name = String::from(name);
    z_name.push_str(".z");

    let x = pubkey::token_mpi(
        keyparam,
        std::ffi::CString::new(x_name)
            .expect("x")
            .as_bytes_with_nul(),
        GCRYMPI_FMT_USG,
    )
    .into_raw();
    let y = pubkey::token_mpi(
        keyparam,
        std::ffi::CString::new(y_name)
            .expect("y")
            .as_bytes_with_nul(),
        GCRYMPI_FMT_USG,
    )
    .into_raw();
    if x.is_null() || y.is_null() {
        gcry_mpi_release(x);
        gcry_mpi_release(y);
        return Ok(null_mut());
    }
    let z = pubkey::token_mpi(
        keyparam,
        std::ffi::CString::new(z_name)
            .expect("z")
            .as_bytes_with_nul(),
        GCRYMPI_FMT_USG,
    )
    .into_raw();

    let point = LocalPoint {
        x,
        y,
        z: if z.is_null() {
            super::gcry_mpi_set_ui(null_mut(), 1)
        } else {
            z
        },
    };
    let mut point = Box::new(point);
    if point.z.is_null() {
        point.z = super::gcry_mpi_new(0);
        super::gcry_mpi_set_ui(point.z, 1);
    }
    Ok(Box::into_raw(point))
}

fn ensure_point_on_curve(point: &PointValue, ctx: &EcContext) -> bool {
    match ctx.model() {
        CurveModel::Weierstrass => {
            let PointValue::Affine(point) = point else {
                return false;
            };
            let Some(p) = mpz_from_mpi(ctx.p) else {
                return false;
            };
            if unsafe { __gmpz_cmp(point.x.as_ptr(), p.as_ptr()) } >= 0
                || unsafe { __gmpz_cmp(point.y.as_ptr(), p.as_ptr()) } >= 0
            {
                return false;
            }
            let Some(a) = mpz_from_mpi(ctx.a) else {
                return false;
            };
            let Some(b) = mpz_from_mpi(ctx.b) else {
                return false;
            };
            let lhs = square_mod(&point.y, &p);
            let rhs = add_mod(
                &add_mod(
                    &mul_mod(&square_mod(&point.x, &p), &point.x, &p),
                    &mul_mod(&a, &point.x, &p),
                    &p,
                ),
                &b,
                &p,
            );
            mod_eq(&lhs, &rhs, &p)
        }
        CurveModel::Edwards => match point {
            PointValue::EdwardsIdentity => true,
            PointValue::Affine(point) => {
                let Some(p) = mpz_from_mpi(ctx.p) else {
                    return false;
                };
                if unsafe { __gmpz_cmp(point.x.as_ptr(), p.as_ptr()) } >= 0
                    || unsafe { __gmpz_cmp(point.y.as_ptr(), p.as_ptr()) } >= 0
                {
                    return false;
                }
                let Some(a) = mpz_from_mpi(ctx.a) else {
                    return false;
                };
                let Some(d) = mpz_from_mpi(ctx.b) else {
                    return false;
                };
                let x2 = square_mod(&point.x, &p);
                let y2 = square_mod(&point.y, &p);
                let lhs = add_mod(&mul_mod(&a, &x2, &p), &y2, &p);
                let rhs = add_mod(
                    &Mpz::from_ui(1),
                    &mul_mod(&d, &mul_mod(&x2, &y2, &p), &p),
                    &p,
                );
                mod_eq(&lhs, &rhs, &p)
            }
            PointValue::Infinity => false,
        },
        CurveModel::Montgomery => true,
    }
}

fn weier_add(p1: PointValue, p2: PointValue, ctx: &EcContext) -> Option<PointValue> {
    match (p1, p2) {
        (PointValue::Infinity, other) | (other, PointValue::Infinity) => Some(other),
        (PointValue::Affine(left), PointValue::Affine(right)) => {
            let modu = mpz_from_mpi(ctx.p)?;
            let a = mpz_from_mpi(ctx.a)?;
            if unsafe { __gmpz_cmp(left.x.as_ptr(), right.x.as_ptr()) } == 0 {
                let y_sum = add_mod(&left.y, &right.y, &modu);
                if mpz_is_zero(&y_sum) {
                    return Some(PointValue::Infinity);
                }
                let three = Mpz::from_ui(3);
                let two = Mpz::from_ui(2);
                let numerator = add_mod(
                    &mul_mod(&three, &square_mod(&left.x, &modu), &modu),
                    &a,
                    &modu,
                );
                let denominator = mul_mod(&two, &left.y, &modu);
                let lambda =
                    inv_mod(&denominator, &modu).map(|inv| mul_mod(&numerator, &inv, &modu))?;
                let x3 = sub_mod(
                    &sub_mod(&square_mod(&lambda, &modu), &left.x, &modu),
                    &right.x,
                    &modu,
                );
                let y3 = sub_mod(
                    &mul_mod(&lambda, &sub_mod(&left.x, &x3, &modu), &modu),
                    &left.y,
                    &modu,
                );
                Some(PointValue::Affine(AffinePoint { x: x3, y: y3 }))
            } else {
                let numerator = sub_mod(&right.y, &left.y, &modu);
                let denominator = sub_mod(&right.x, &left.x, &modu);
                let lambda =
                    inv_mod(&denominator, &modu).map(|inv| mul_mod(&numerator, &inv, &modu))?;
                let x3 = sub_mod(
                    &sub_mod(&square_mod(&lambda, &modu), &left.x, &modu),
                    &right.x,
                    &modu,
                );
                let y3 = sub_mod(
                    &mul_mod(&lambda, &sub_mod(&left.x, &x3, &modu), &modu),
                    &left.y,
                    &modu,
                );
                Some(PointValue::Affine(AffinePoint { x: x3, y: y3 }))
            }
        }
        _ => None,
    }
}

fn edwards_add(p1: PointValue, p2: PointValue, ctx: &EcContext) -> Option<PointValue> {
    match (p1, p2) {
        (PointValue::EdwardsIdentity, other) | (other, PointValue::EdwardsIdentity) => Some(other),
        (PointValue::Affine(left), PointValue::Affine(right)) => {
            let modu = mpz_from_mpi(ctx.p)?;
            let a = mpz_from_mpi(ctx.a)?;
            let d = mpz_from_mpi(ctx.b)?;
            let x1y2 = mul_mod(&left.x, &right.y, &modu);
            let y1x2 = mul_mod(&left.y, &right.x, &modu);
            let y1y2 = mul_mod(&left.y, &right.y, &modu);
            let x1x2 = mul_mod(&left.x, &right.x, &modu);
            let dxxyy = mul_mod(&d, &mul_mod(&x1x2, &y1y2, &modu), &modu);
            let one = Mpz::from_ui(1);

            let x_num = add_mod(&x1y2, &y1x2, &modu);
            let x_den = add_mod(&one, &dxxyy, &modu);
            let y_num = sub_mod(&y1y2, &mul_mod(&a, &x1x2, &modu), &modu);
            let y_den = sub_mod(&one, &dxxyy, &modu);
            let x = inv_mod(&x_den, &modu).map(|inv| mul_mod(&x_num, &inv, &modu))?;
            let y = inv_mod(&y_den, &modu).map(|inv| mul_mod(&y_num, &inv, &modu))?;
            if mpz_is_zero(&x) && unsafe { __gmpz_cmp_ui(y.as_ptr(), 1) == 0 } {
                Some(PointValue::EdwardsIdentity)
            } else {
                Some(PointValue::Affine(AffinePoint { x, y }))
            }
        }
        _ => None,
    }
}

fn point_neg(point: PointValue, ctx: &EcContext) -> PointValue {
    match (ctx.model(), point) {
        (_, PointValue::Infinity) => PointValue::Infinity,
        (CurveModel::Edwards, PointValue::EdwardsIdentity) => PointValue::EdwardsIdentity,
        (CurveModel::Edwards, PointValue::Affine(point)) => {
            let modu = mpz_from_mpi(ctx.p).expect("edwards p");
            PointValue::Affine(AffinePoint {
                x: neg_mod(&point.x, &modu),
                y: point.y,
            })
        }
        (_, PointValue::Affine(point)) => {
            let modu = mpz_from_mpi(ctx.p).expect("curve p");
            PointValue::Affine(AffinePoint {
                x: point.x,
                y: neg_mod(&point.y, &modu),
            })
        }
        (_, PointValue::EdwardsIdentity) => PointValue::EdwardsIdentity,
    }
}

fn scalar_bits(value: &Mpz) -> usize {
    if mpz_is_zero(value) {
        0
    } else {
        unsafe { __gmpz_sizeinbase(value.as_ptr(), 2) }
    }
}

fn scalar_reduce(ctx: &EcContext, scalar: &Mpz) -> Mpz {
    if ctx.model() == CurveModel::Montgomery || ctx.n.is_null() {
        return Mpz::clone_from(scalar.as_ptr());
    }
    let n = mpz_from_mpi(ctx.n).expect("order");
    let mut out = Mpz::new(0);
    unsafe {
        __gmpz_mod(out.as_mut_ptr(), scalar.as_ptr(), n.as_ptr());
    }
    out
}

fn scalar_mul_affine(base: PointValue, scalar: &Mpz, ctx: &EcContext) -> Option<PointValue> {
    let scalar = scalar_reduce(ctx, scalar);
    let mut result = match ctx.model() {
        CurveModel::Edwards => PointValue::EdwardsIdentity,
        _ => PointValue::Infinity,
    };
    let mut addend = base;
    for bit in 0..scalar_bits(&scalar) {
        if unsafe { __gmpz_tstbit(scalar.as_ptr(), bit) != 0 } {
            result = match ctx.model() {
                CurveModel::Edwards => edwards_add(result, addend.clone(), ctx)?,
                _ => weier_add(result, addend.clone(), ctx)?,
            };
        }
        addend = match ctx.model() {
            CurveModel::Edwards => edwards_add(addend.clone(), addend, ctx)?,
            _ => weier_add(addend.clone(), addend, ctx)?,
        };
    }
    Some(result)
}

fn montgomery_ladder(scalar: &Mpz, u: &Mpz, ctx: &EcContext) -> Option<Mpz> {
    let p = mpz_from_mpi(ctx.p)?;
    let a24 = match ctx.curve.map(|curve| curve.canonical) {
        Some("Curve25519") => Mpz::from_ui(121665),
        Some("X448") => Mpz::from_ui(39081),
        _ => return None,
    };

    let mut x2 = Mpz::from_ui(1);
    let mut z2 = Mpz::from_ui(0);
    let mut x3 = Mpz::clone_from(u.as_ptr());
    let mut z3 = Mpz::from_ui(1);
    let x1 = Mpz::clone_from(u.as_ptr());
    let bits = ctx.nbits() as usize;

    let mut swap = false;
    for bit in (0..bits).rev() {
        let k_bit = unsafe { __gmpz_tstbit(scalar.as_ptr(), bit) != 0 };
        if swap != k_bit {
            std::mem::swap(&mut x2, &mut x3);
            std::mem::swap(&mut z2, &mut z3);
        }
        swap = k_bit;

        let a = add_mod(&x2, &z2, &p);
        let aa = square_mod(&a, &p);
        let b = sub_mod(&x2, &z2, &p);
        let bb = square_mod(&b, &p);
        let e = sub_mod(&aa, &bb, &p);
        let c = add_mod(&x3, &z3, &p);
        let d = sub_mod(&x3, &z3, &p);
        let da = mul_mod(&d, &a, &p);
        let cb = mul_mod(&c, &b, &p);
        let da_plus_cb = add_mod(&da, &cb, &p);
        let da_minus_cb = sub_mod(&da, &cb, &p);
        x3 = square_mod(&da_plus_cb, &p);
        z3 = mul_mod(&x1, &square_mod(&da_minus_cb, &p), &p);
        x2 = mul_mod(&aa, &bb, &p);
        z2 = mul_mod(&e, &add_mod(&aa, &mul_mod(&a24, &e, &p), &p), &p);
    }
    if swap {
        std::mem::swap(&mut x2, &mut x3);
        std::mem::swap(&mut z2, &mut z3);
    }

    if mpz_is_zero(&z2) {
        return Some(Mpz::from_ui(0));
    }

    inv_mod(&z2, &p).map(|inv| mul_mod(&x2, &inv, &p))
}

fn encode_sec1(point: &PointValue, ctx: &EcContext) -> Option<*mut gcry_mpi> {
    let PointValue::Affine(point) = point else {
        return None;
    };
    let nbytes = point_coordinate_bytes(ctx);
    let mut bytes = Vec::with_capacity(1 + (2 * nbytes));
    bytes.push(0x04);
    bytes.extend_from_slice(&mpz_to_fixed_be(&point.x, nbytes));
    bytes.extend_from_slice(&mpz_to_fixed_be(&point.y, nbytes));
    Some(super::opaque::gcry_mpi_set_opaque_copy(
        null_mut(),
        bytes.as_ptr().cast(),
        (bytes.len() * 8) as c_uint,
    ))
}

fn encode_eddsa(point: &PointValue, ctx: &EcContext) -> Option<*mut gcry_mpi> {
    let point = match point {
        PointValue::EdwardsIdentity => AffinePoint {
            x: Mpz::from_ui(0),
            y: Mpz::from_ui(1),
        },
        PointValue::Affine(point) => point.clone(),
        PointValue::Infinity => return None,
    };
    let len = eddsa_encoding_bytes(ctx.nbits());
    let mut bytes = mpz_to_le_fixed(&point.y, len);
    if mpz_is_odd(&point.x) {
        bytes[len - 1] |= 0x80;
    }
    Some(super::opaque::gcry_mpi_set_opaque_copy(
        null_mut(),
        bytes.as_ptr().cast(),
        (bytes.len() * 8) as c_uint,
    ))
}

fn encode_montgomery(point: &PointValue, ctx: &EcContext) -> Option<*mut gcry_mpi> {
    let PointValue::Affine(point) = point else {
        return None;
    };
    let nbytes = bytes_for_bits(ctx.nbits());
    let mut bytes = mpz_to_le_fixed(&point.x, nbytes);
    if ctx.curve.is_some_and(|curve| curve.montgomery_prefix) {
        bytes.insert(0, 0x40);
    }
    Some(super::opaque::gcry_mpi_set_opaque_copy(
        null_mut(),
        bytes.as_ptr().cast(),
        (bytes.len() * 8) as c_uint,
    ))
}

fn point_to_mpi(name: &str, point: &PointValue, ctx: &EcContext) -> Option<*mut gcry_mpi> {
    match name {
        "g" | "q" => match ctx.model() {
            CurveModel::Montgomery => encode_montgomery(point, ctx),
            _ => encode_sec1(point, ctx),
        },
        "q@eddsa" if ctx.curve.is_some_and(|curve| curve.eddsa) => encode_eddsa(point, ctx),
        _ => None,
    }
}

fn opaque_secret_from_bytes(bytes: &[u8], secure: bool) -> Result<pubkey::OwnedMpi, u32> {
    let ptr = super::alloc_output_bytes(bytes, secure);
    if ptr.is_null() && !bytes.is_empty() {
        return Err(error::gcry_error_from_errno(crate::ENOMEM_VALUE));
    }
    Ok(pubkey::OwnedMpi::new(super::opaque::gcry_mpi_set_opaque(
        null_mut(),
        ptr,
        (bytes.len() * 8) as c_uint,
    )))
}

fn named_context_opaque_secret(keyparam: *mut sexp::gcry_sexp, curve: &CurveDef) -> bool {
    curve.model == CurveModel::Montgomery || named_context_eddsa_secret(keyparam, curve)
}

fn named_context_eddsa_secret(keyparam: *mut sexp::gcry_sexp, curve: &CurveDef) -> bool {
    curve.canonical == "Ed448" || (curve.eddsa && pubkey::flag_present(keyparam, b"eddsa\0"))
}

fn normalize_named_opaque_secret(
    d: pubkey::OwnedMpi,
    curve: &CurveDef,
) -> Result<pubkey::OwnedMpi, u32> {
    if d.is_null() {
        return Ok(d);
    }

    let have = pubkey::mpi_to_bytes(d.raw())
        .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))?;
    let want = if curve.eddsa {
        eddsa_encoding_bytes(curve.nbits)
    } else {
        bytes_for_bits(curve.nbits)
    };
    if have.len() == want {
        return Ok(d);
    }

    if curve.canonical != "Ed25519" {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    }

    let normalized = if have.len() < want {
        let mut bytes = vec![0u8; want - have.len()];
        bytes.extend_from_slice(&have);
        bytes
    } else if have.len() == want + 1 && have.first() == Some(&0) {
        have[1..].to_vec()
    } else {
        return Err(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    };

    opaque_secret_from_bytes(&normalized, mpi_secure(d.raw()))
}

fn parse_named_context(
    keyparam: *mut sexp::gcry_sexp,
    curve: &'static CurveDef,
) -> Result<EcContext, u32> {
    let mut ctx =
        context_from_curve(curve).ok_or(error::gcry_error_from_code(error::GPG_ERR_INV_OBJ))?;

    if !keyparam.is_null() {
        ctx.eddsa_secret = named_context_eddsa_secret(keyparam, curve);
        let q = point_from_keyparam(keyparam, "q", Some(&ctx))?;
        if !q.is_null() {
            ctx.q = q;
        }
        let opaque_secret = named_context_opaque_secret(keyparam, curve);
        let d = pubkey::token_mpi(
            keyparam,
            b"d\0",
            if opaque_secret {
                GCRYMPI_FMT_OPAQUE
            } else {
                GCRYMPI_FMT_USG
            },
        );
        ctx.d = if opaque_secret {
            normalize_named_opaque_secret(d, curve)?.into_raw()
        } else {
            d.into_raw()
        };
    }

    Ok(ctx)
}

fn clamp_montgomery_scalar(curve: &CurveDef, bytes: &[u8]) -> Option<Mpz> {
    let nbytes = bytes_for_bits(curve.nbits);
    if nbytes == 0 {
        return None;
    }

    let mut scalar = bytes.to_vec();
    scalar.truncate(nbytes);
    scalar.resize(nbytes, 0);

    match curve.canonical {
        "Curve25519" => {
            scalar[0] &= 248;
            scalar[nbytes - 1] &= 127;
            scalar[nbytes - 1] |= 64;
        }
        "X448" => {
            scalar[0] &= 252;
            scalar[nbytes - 1] |= 128;
        }
        _ => return None,
    }

    Some(mpz_from_le(&scalar))
}

fn hash_shake256(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut state = Shake256::default();
    state.update(input);
    let mut reader = state.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

fn eddsa_secret_scalar(curve: &CurveDef, seed: &[u8]) -> Option<Mpz> {
    let b = match curve.canonical {
        "Ed25519" => 32usize,
        "Ed448" => 57usize,
        _ => return None,
    };

    let digest = match curve.canonical {
        "Ed25519" => Sha512::digest(seed).to_vec(),
        "Ed448" => hash_shake256(seed, 2 * b),
        _ => return None,
    };
    if digest.len() < 2 * b {
        return None;
    }

    let mut scalar = digest[..b].to_vec();
    scalar.reverse();
    match curve.canonical {
        "Ed25519" => {
            scalar[0] = (scalar[0] & 0x7f) | 0x40;
            scalar[b - 1] &= 0xf8;
        }
        "Ed448" => {
            scalar[0] = 0;
            scalar[1] |= 0x80;
            scalar[b - 1] &= 0xfc;
        }
        _ => return None,
    }

    Some(import_unsigned_bytes(&scalar))
}

fn eddsa_seed_from_numeric(curve: &CurveDef, value: &Mpz) -> Option<Vec<u8>> {
    let b = match curve.canonical {
        "Ed25519" => 32usize,
        "Ed448" => 57usize,
        _ => return None,
    };
    let mut seed = export_unsigned(value.as_ptr());
    if seed.len() < b {
        let mut padded = vec![0u8; b - seed.len()];
        padded.extend_from_slice(&seed);
        seed = padded;
    }
    Some(seed)
}

fn scalar_from_mpi_for_curve(ptr: *mut gcry_mpi, ctx: &EcContext) -> Option<Mpz> {
    let mpi = unsafe { gcry_mpi::as_ref(ptr) }?;
    match &mpi.kind {
        MpiKind::Numeric(value) => {
            if ctx.eddsa_secret && ptr == ctx.d {
                eddsa_secret_scalar(ctx.curve?, &eddsa_seed_from_numeric(ctx.curve?, value)?)
            } else {
                Some(Mpz::clone_from(value.as_ptr()))
            }
        }
        MpiKind::Opaque(value) => {
            let curve = ctx.curve?;
            if curve.model == CurveModel::Montgomery {
                clamp_montgomery_scalar(curve, value.as_slice())
            } else if ctx.eddsa_secret {
                eddsa_secret_scalar(curve, value.as_slice())
            } else {
                None
            }
        }
    }
}

fn register_context(ptr: *mut EcContext) {
    lock_registry().insert(ptr as usize);
}

fn unregister_context(ptr: *mut c_void) -> bool {
    lock_registry().remove(&(ptr as usize))
}

pub(crate) fn is_local_context(ctx: *mut c_void) -> bool {
    if ctx.is_null() {
        return false;
    }
    lock_registry().contains(&(ctx as usize))
}

pub(crate) fn release_local_context(ctx: *mut c_void) -> bool {
    if !unregister_context(ctx) {
        return false;
    }
    unsafe {
        drop(Box::from_raw(ctx.cast::<EcContext>()));
    }
    true
}

fn ensure_public_point(ctx: &mut EcContext) -> Option<()> {
    if !ctx.q.is_null() {
        return Some(());
    }
    let mut q = LocalPoint::boxed();
    let ctx_ptr = (ctx as *mut EcContext).cast();
    gcry_mpi_ec_mul(
        (&mut *q as *mut LocalPoint).cast(),
        ctx.d,
        ctx.g.cast(),
        ctx_ptr,
    );
    point_value_from_handle(q.as_ref(), ctx)?;
    ctx.q = Box::into_raw(q);
    Some(())
}

pub(crate) fn pk_get_curve_name(
    key: *mut sexp::gcry_sexp,
    iterator: c_int,
    nbits: *mut c_uint,
) -> *const c_char {
    if !nbits.is_null() {
        unsafe {
            *nbits = 0;
        }
    }

    if key.is_null() {
        let Some(curve) = curve_by_index(iterator) else {
            return std::ptr::null();
        };
        if !nbits.is_null() {
            unsafe {
                *nbits = curve.nbits;
            }
        }
        return curve.canonical_cstr.as_ptr().cast();
    }

    if iterator != 0 {
        return std::ptr::null();
    }

    if let Some(name) = pubkey::token_string_value(key, b"curve\0") {
        if let Some(curve) = curve_by_name(&name).filter(|curve| curve_allowed(curve)) {
            if !nbits.is_null() {
                unsafe {
                    *nbits = curve.nbits;
                }
            }
            return curve.canonical_cstr.as_ptr().cast();
        }
    }

    if let Some(curve) = curve_matches_params(key).filter(|curve| curve_allowed(curve)) {
        if !nbits.is_null() {
            unsafe {
                *nbits = curve.nbits;
            }
        }
        return curve.canonical_cstr.as_ptr().cast();
    }

    std::ptr::null()
}

pub(crate) fn pk_get_param_sexp(algo: c_int, name: *const c_char) -> *mut sexp::gcry_sexp {
    if !pubkey::family_from_algorithm(algo).is_some_and(|family| family == pubkey::Family::Ecc) {
        return null_mut();
    }
    if name.is_null() {
        return null_mut();
    }

    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    let Some(curve) = curve_by_name(&name).filter(|curve| curve_allowed(curve)) else {
        return null_mut();
    };

    if curve.eddsa {
        pubkey::build_sexp(
            "(public-key(ecc(curve %s)(flags eddsa)))",
            &[pubkey::ptr_to_arg(curve.canonical_cstr.as_ptr())],
        )
        .unwrap_or(null_mut())
    } else if curve.model == CurveModel::Montgomery && curve.canonical == "Curve25519" {
        pubkey::build_sexp(
            "(public-key(ecc(curve %s)(flags djb-tweak)))",
            &[pubkey::ptr_to_arg(curve.canonical_cstr.as_ptr())],
        )
        .unwrap_or(null_mut())
    } else {
        pubkey::build_sexp(
            "(public-key(ecc(curve %s)))",
            &[pubkey::ptr_to_arg(curve.canonical_cstr.as_ptr())],
        )
        .unwrap_or(null_mut())
    }
}

pub(crate) fn ecc_get_algo_keylen(curveid: c_int) -> c_uint {
    match curveid {
        GCRY_ECC_CURVE25519 => 32,
        GCRY_ECC_CURVE448 => 56,
        _ => 0,
    }
}

fn ecc_mul_curve(curveid: c_int) -> Option<&'static CurveDef> {
    match curveid {
        GCRY_ECC_CURVE25519 => curve_by_canonical("Curve25519"),
        GCRY_ECC_CURVE448 => curve_by_canonical("X448"),
        _ => None,
    }
}

pub(crate) fn ecc_mul_point_bytes(
    curveid: c_int,
    result: *mut u8,
    scalar: *const u8,
    point: *const u8,
) -> u32 {
    if result.is_null() || scalar.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }

    let Some(curve) = ecc_mul_curve(curveid) else {
        return error::gcry_error_from_code(GPG_ERR_UNKNOWN_CURVE);
    };
    if !curve_allowed(curve) {
        return error::gcry_error_from_code(error::GPG_ERR_NOT_SUPPORTED);
    }

    let Some(mut ctx) = context_from_curve(curve) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };
    let nbytes = bytes_for_bits(curve.nbits);
    let scalar_bytes = unsafe { std::slice::from_raw_parts(scalar, nbytes) };
    let scalar_mpi = match opaque_secret_from_bytes(scalar_bytes, true) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let point_storage = if point.is_null() {
        None
    } else {
        let point_bytes = unsafe { std::slice::from_raw_parts(point, nbytes) };
        let Some(value) = decode_point_bytes(&ctx, point_bytes) else {
            return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
        };
        let mut local = LocalPoint::boxed();
        write_point_value(&mut local, value, false);
        Some(local)
    };

    let source = if point.is_null() {
        match unsafe { LocalPoint::as_ref(ctx.g.cast()) } {
            Some(value) => value,
            None => return error::gcry_error_from_code(GPG_ERR_BAD_CRYPT_CTX),
        }
    } else {
        point_storage.as_deref().expect("decoded point")
    };

    let mut output = LocalPoint::boxed();
    gcry_mpi_ec_mul(
        (&mut *output as *mut LocalPoint).cast(),
        scalar_mpi.raw(),
        (source as *const LocalPoint).cast_mut().cast(),
        (&mut ctx as *mut EcContext).cast(),
    );

    let bytes = match point_value_from_handle(output.as_ref(), &ctx) {
        Some(PointValue::Affine(point)) => mpz_to_le_fixed(&point.x, nbytes),
        Some(PointValue::Infinity) | None => vec![0u8; nbytes],
        Some(PointValue::EdwardsIdentity) => return error::gcry_error_from_code(GPG_ERR_BAD_CRYPT_CTX),
    };
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), result, nbytes);
    }
    0
}

pub(crate) fn local_pubkey_get_sexp(
    result: *mut *mut sexp::gcry_sexp,
    mode: c_int,
    ctx: *mut c_void,
) -> u32 {
    let Some(ctx) = (unsafe { EcContext::as_mut(ctx) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    if ctx.p.is_null() || ctx.a.is_null() || ctx.b.is_null() || ctx.g.is_null() || ctx.n.is_null() {
        return error::gcry_error_from_code(GPG_ERR_BAD_CRYPT_CTX);
    }
    if mode == pubkey::GCRY_PK_GET_SECKEY && ctx.d.is_null() {
        return error::gcry_error_from_code(GPG_ERR_NO_SECKEY);
    }
    if ctx.q.is_null() && !ctx.d.is_null() && ensure_public_point(ctx).is_none() {
        return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
    }
    if ctx.q.is_null() {
        return error::gcry_error_from_code(GPG_ERR_BAD_CRYPT_CTX);
    }

    let Some(g_value) =
        point_value_from_handle(unsafe { LocalPoint::as_ref(ctx.g.cast()) }.expect("g"), ctx)
    else {
        return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
    };
    let Some(q_value) =
        point_value_from_handle(unsafe { LocalPoint::as_ref(ctx.q.cast()) }.expect("q"), ctx)
    else {
        return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
    };
    let Some(g_mpi) = encode_sec1(&g_value, ctx) else {
        return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
    };
    let q_mpi = match ctx.model() {
        CurveModel::Edwards if ctx.curve.is_some_and(|curve| curve.eddsa) => {
            encode_eddsa(&q_value, ctx)
        }
        CurveModel::Montgomery => encode_montgomery(&q_value, ctx),
        _ => encode_sec1(&q_value, ctx),
    };
    let Some(q_mpi) = q_mpi else {
        gcry_mpi_release(g_mpi);
        return error::gcry_error_from_code(GPG_ERR_BROKEN_PUBKEY);
    };

    let built = if !ctx.d.is_null() && (mode == 0 || mode == pubkey::GCRY_PK_GET_SECKEY) {
        pubkey::build_sexp(
            "(private-key(ecc(p%m)(a%m)(b%m)(g%m)(n%m)(h%u)(q%m)(d%m)))",
            &[
                pubkey::ptr_to_arg(ctx.p),
                pubkey::ptr_to_arg(ctx.a),
                pubkey::ptr_to_arg(ctx.b),
                pubkey::ptr_to_arg(g_mpi),
                pubkey::ptr_to_arg(ctx.n),
                pubkey::usize_to_arg(ctx.h as usize),
                pubkey::ptr_to_arg(q_mpi),
                pubkey::ptr_to_arg(ctx.d),
            ],
        )
    } else {
        pubkey::build_sexp(
            "(public-key(ecc(p%m)(a%m)(b%m)(g%m)(n%m)(h%u)(q%m)))",
            &[
                pubkey::ptr_to_arg(ctx.p),
                pubkey::ptr_to_arg(ctx.a),
                pubkey::ptr_to_arg(ctx.b),
                pubkey::ptr_to_arg(g_mpi),
                pubkey::ptr_to_arg(ctx.n),
                pubkey::usize_to_arg(ctx.h as usize),
                pubkey::ptr_to_arg(q_mpi),
            ],
        )
    };

    gcry_mpi_release(g_mpi);
    gcry_mpi_release(q_mpi);

    match built {
        Ok(value) => {
            unsafe {
                *result = value;
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_new(_nbits: c_uint) -> *mut c_void {
    Box::into_raw(LocalPoint::boxed()).cast()
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_release(point: *mut c_void) {
    if !point.is_null() {
        unsafe {
            drop(Box::from_raw(point.cast::<LocalPoint>()));
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_copy(point: *mut c_void) -> *mut c_void {
    cloned_point(point)
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_get(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
    point: *mut c_void,
) {
    let Some(point) = (unsafe { LocalPoint::as_ref(point) }) else {
        zero_target(x);
        zero_target(y);
        zero_target(z);
        return;
    };
    if !x.is_null() {
        super::gcry_mpi_set(x, point.x);
    }
    if !y.is_null() {
        super::gcry_mpi_set(y, point.y);
    }
    if !z.is_null() {
        super::gcry_mpi_set(z, point.z);
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_snatch_get(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
    point: *mut c_void,
) {
    let Some(point) =
        (!point.is_null()).then(|| unsafe { Box::from_raw(point.cast::<LocalPoint>()) })
    else {
        zero_target(x);
        zero_target(y);
        zero_target(z);
        return;
    };

    if !x.is_null() {
        super::gcry_mpi_set(x, point.x);
    }
    if !y.is_null() {
        super::gcry_mpi_set(y, point.y);
    }
    if !z.is_null() {
        super::gcry_mpi_set(z, point.z);
    }
    reset_coord(point.x);
    reset_coord(point.y);
    reset_coord(point.z);
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_set(
    point: *mut c_void,
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
) -> *mut c_void {
    let point = ensure_point(point);
    let point_ref = unsafe { &mut *point };
    if x.is_null() {
        reset_coord(point_ref.x);
    } else {
        super::gcry_mpi_set(point_ref.x, x);
    }
    if y.is_null() {
        reset_coord(point_ref.y);
    } else {
        super::gcry_mpi_set(point_ref.y, y);
    }
    if z.is_null() {
        reset_coord(point_ref.z);
    } else {
        super::gcry_mpi_set(point_ref.z, z);
    }
    point.cast()
}

#[no_mangle]
pub extern "C" fn gcry_mpi_point_snatch_set(
    point: *mut c_void,
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    z: *mut gcry_mpi,
) -> *mut c_void {
    let point = ensure_point(point);
    let point_ref = unsafe { &mut *point };

    if x.is_null() {
        reset_coord(point_ref.x);
    } else {
        replace_mpi(&mut point_ref.x, x);
    }
    if y.is_null() {
        reset_coord(point_ref.y);
    } else {
        replace_mpi(&mut point_ref.y, y);
    }
    if z.is_null() {
        reset_coord(point_ref.z);
    } else {
        replace_mpi(&mut point_ref.z, z);
    }
    point.cast()
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_new(
    r_ctx: *mut *mut c_void,
    keyparam: *mut sexp::gcry_sexp,
    curvename: *const c_char,
) -> u32 {
    if r_ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    unsafe {
        *r_ctx = null_mut();
    }

    if legacy_ecdsa_param_error(keyparam, curvename) {
        return error::gcry_error_from_errno(crate::EINVAL_VALUE);
    }

    let curve = if !keyparam.is_null() {
        pubkey::token_string_value(keyparam, b"curve\0").and_then(|name| curve_by_name(&name))
    } else {
        None
    }
    .or_else(|| {
        (!curvename.is_null())
            .then(|| unsafe { CStr::from_ptr(curvename) })
            .and_then(|name| curve_by_name(&name.to_string_lossy()))
    })
    .or_else(|| {
        (!keyparam.is_null())
            .then(|| curve_matches_params(keyparam))
            .flatten()
    });

    let ctx = if let Some(curve) = curve.filter(|curve| curve_allowed(curve)) {
        parse_named_context(keyparam, curve)
    } else if curve.is_some() {
        Err(error::gcry_error_from_code(GPG_ERR_UNKNOWN_CURVE))
    } else if keyparam.is_null() {
        Err(error::gcry_error_from_errno(crate::EINVAL_VALUE))
    } else {
        parse_custom_context(keyparam).ok_or(error::gcry_error_from_errno(crate::EINVAL_VALUE))
    };

    match ctx {
        Ok(ctx) => {
            let raw = Box::into_raw(Box::new(ctx));
            register_context(raw);
            unsafe {
                *r_ctx = raw.cast();
            }
            0
        }
        Err(err) => err,
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_get_mpi(
    name: *const c_char,
    ctx: *mut c_void,
    _copy: c_int,
) -> *mut gcry_mpi {
    if name.is_null() || ctx.is_null() {
        return null_mut();
    }
    let Some(ctx) = (unsafe { EcContext::as_mut(ctx) }) else {
        return null_mut();
    };
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    match name.as_ref() {
        "p" => gcry_mpi_copy(ctx.p),
        "a" => gcry_mpi_copy(ctx.a),
        "b" => gcry_mpi_copy(ctx.b),
        "n" => gcry_mpi_copy(ctx.n),
        "h" => h_to_mpi(ctx.h),
        "d" => gcry_mpi_copy(ctx.d),
        "g.x" => unsafe { LocalPoint::as_ref(ctx.g.cast()) }
            .map_or(null_mut(), |point| gcry_mpi_copy(point.x)),
        "g.y" => unsafe { LocalPoint::as_ref(ctx.g.cast()) }
            .map_or(null_mut(), |point| gcry_mpi_copy(point.y)),
        "q.x" => {
            if ctx.q.is_null() && ensure_public_point(ctx).is_none() {
                return null_mut();
            }
            unsafe { LocalPoint::as_ref(ctx.q.cast()) }
                .map_or(null_mut(), |point| gcry_mpi_copy(point.x))
        }
        "q.y" => {
            if ctx.q.is_null() && ensure_public_point(ctx).is_none() {
                return null_mut();
            }
            unsafe { LocalPoint::as_ref(ctx.q.cast()) }
                .map_or(null_mut(), |point| gcry_mpi_copy(point.y))
        }
        "g" => unsafe { LocalPoint::as_ref(ctx.g.cast()) }
            .and_then(|point| point_value_from_handle(point, ctx))
            .and_then(|point| point_to_mpi("g", &point, ctx))
            .unwrap_or(null_mut()),
        "q" => {
            if ctx.q.is_null() && ensure_public_point(ctx).is_none() {
                return null_mut();
            }
            unsafe { LocalPoint::as_ref(ctx.q.cast()) }
                .and_then(|point| point_value_from_handle(point, ctx))
                .and_then(|point| point_to_mpi("q", &point, ctx))
                .unwrap_or(null_mut())
        }
        "q@eddsa" => {
            if ctx.q.is_null() && ensure_public_point(ctx).is_none() {
                return null_mut();
            }
            unsafe { LocalPoint::as_ref(ctx.q.cast()) }
                .and_then(|point| point_value_from_handle(point, ctx))
                .and_then(|point| point_to_mpi("q@eddsa", &point, ctx))
                .unwrap_or(null_mut())
        }
        _ => null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_get_point(
    name: *const c_char,
    ctx: *mut c_void,
    _copy: c_int,
) -> *mut c_void {
    if name.is_null() || ctx.is_null() {
        return null_mut();
    }
    let Some(ctx) = (unsafe { EcContext::as_mut(ctx) }) else {
        return null_mut();
    };
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    match name.as_ref() {
        "g" => cloned_point(ctx.g.cast()),
        "q" => {
            if ctx.q.is_null() && ensure_public_point(ctx).is_none() {
                return null_mut();
            }
            cloned_point(ctx.q.cast())
        }
        _ => null_mut(),
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_set_mpi(
    name: *const c_char,
    newvalue: *mut gcry_mpi,
    ctx: *mut c_void,
) -> u32 {
    if name.is_null() || ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let Some(ctx) = (unsafe { EcContext::as_mut(ctx) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    match name.as_ref() {
        "p" => replace_mpi(&mut ctx.p, gcry_mpi_copy(newvalue)),
        "a" => replace_mpi(&mut ctx.a, gcry_mpi_copy(newvalue)),
        "b" => replace_mpi(&mut ctx.b, gcry_mpi_copy(newvalue)),
        "n" => replace_mpi(&mut ctx.n, gcry_mpi_copy(newvalue)),
        "h" => {
            let _ = super::gcry_mpi_get_ui(&mut ctx.h, newvalue);
        }
        "d" => {
            replace_mpi(&mut ctx.d, gcry_mpi_copy(newvalue));
            if !ctx.d.is_null() && !ctx.q.is_null() {
                unsafe {
                    drop(Box::from_raw(ctx.q));
                }
                ctx.q = null_mut();
            }
        }
        "q" => {
            if !ctx.q.is_null() {
                unsafe {
                    drop(Box::from_raw(ctx.q));
                }
                ctx.q = null_mut();
            }
            if !newvalue.is_null() {
                let bytes = pubkey::mpi_to_bytes(newvalue);
                let Some(decoded) = bytes.and_then(|bytes| decode_point_bytes(ctx, &bytes)) else {
                    return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
                };
                let mut point = LocalPoint::boxed();
                write_point_value(&mut point, decoded, mpi_secure(newvalue));
                ctx.q = Box::into_raw(point);
            }
        }
        _ => return error::gcry_error_from_code(GPG_ERR_UNKNOWN_NAME),
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_set_point(
    name: *const c_char,
    newvalue: *mut c_void,
    ctx: *mut c_void,
) -> u32 {
    if name.is_null() || ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let Some(ctx) = (unsafe { EcContext::as_mut(ctx) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    let name = unsafe { CStr::from_ptr(name) }.to_string_lossy();
    match name.as_ref() {
        "g" => {
            if !ctx.g.is_null() {
                unsafe {
                    drop(Box::from_raw(ctx.g));
                }
            }
            ctx.g = if newvalue.is_null() {
                null_mut()
            } else {
                cloned_point(newvalue).cast()
            };
        }
        "q" => {
            if !ctx.q.is_null() {
                unsafe {
                    drop(Box::from_raw(ctx.q));
                }
            }
            ctx.q = if newvalue.is_null() {
                null_mut()
            } else {
                cloned_point(newvalue).cast()
            };
        }
        _ => return error::gcry_error_from_code(GPG_ERR_UNKNOWN_NAME),
    }
    0
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_decode_point(
    result: *mut c_void,
    value: *mut gcry_mpi,
    ctx: *mut c_void,
) -> u32 {
    if result.is_null() || ctx.is_null() {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    }
    let Some(ctx) = (unsafe { EcContext::as_ref(ctx) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    let bytes = pubkey::mpi_to_bytes(value)
        .ok_or_else(|| error::gcry_error_from_code(error::GPG_ERR_INV_OBJ));
    let Some(decoded) = bytes.ok().and_then(|bytes| decode_point_bytes(ctx, &bytes)) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_OBJ);
    };
    let Some(point) = (unsafe { LocalPoint::as_mut(result) }) else {
        return error::gcry_error_from_code(error::GPG_ERR_INV_ARG);
    };
    write_point_value(point, decoded, mpi_secure(value));
    0
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_get_affine(
    x: *mut gcry_mpi,
    y: *mut gcry_mpi,
    point: *mut c_void,
    ctx: *mut c_void,
) -> c_int {
    if point.is_null() || ctx.is_null() {
        return -1;
    }
    let Some(ctx) = (unsafe { EcContext::as_ref(ctx) }) else {
        return -1;
    };
    let Some(point) = (unsafe { LocalPoint::as_ref(point) }) else {
        return -1;
    };
    let secure = point_secure(point);
    let Some(value) = point_value_from_handle(point, ctx) else {
        return -1;
    };
    match value {
        PointValue::Infinity => -1,
        PointValue::EdwardsIdentity => {
            if !x.is_null() {
                super::gcry_mpi_set_ui(x, 0);
            }
            if !y.is_null() {
                super::gcry_mpi_set_ui(y, 1);
            }
            0
        }
        PointValue::Affine(point) => {
            if !x.is_null() {
                assign_target_mpi(x, point.x, secure);
            }
            if !y.is_null() {
                assign_target_mpi(y, point.y, secure);
            }
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_dup(w: *mut c_void, u: *mut c_void, _ctx: *mut c_void) {
    if w.is_null() || u.is_null() {
        return;
    }
    let Some(src) = (unsafe { LocalPoint::as_ref(u) }) else {
        return;
    };
    let Some(dest) = (unsafe { LocalPoint::as_mut(w) }) else {
        return;
    };
    super::gcry_mpi_set(dest.x, src.x);
    super::gcry_mpi_set(dest.y, src.y);
    super::gcry_mpi_set(dest.z, src.z);
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_add(
    w: *mut c_void,
    u: *mut c_void,
    v: *mut c_void,
    ctx: *mut c_void,
) {
    if w.is_null() || u.is_null() || v.is_null() || ctx.is_null() {
        return;
    }
    let Some(ctx) = (unsafe { EcContext::as_ref(ctx) }) else {
        return;
    };
    if ctx.model() == CurveModel::Montgomery {
        return;
    }
    let Some(left) =
        (unsafe { LocalPoint::as_ref(u) }).and_then(|point| point_value_from_handle(point, ctx))
    else {
        return;
    };
    let Some(right) =
        (unsafe { LocalPoint::as_ref(v) }).and_then(|point| point_value_from_handle(point, ctx))
    else {
        return;
    };
    let result = match ctx.model() {
        CurveModel::Edwards => edwards_add(left, right, ctx),
        _ => weier_add(left, right, ctx),
    };
    let Some(result) = result else {
        return;
    };
    if let Some(dest) = unsafe { LocalPoint::as_mut(w) } {
        write_point_value(dest, result, false);
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_sub(
    w: *mut c_void,
    u: *mut c_void,
    v: *mut c_void,
    ctx: *mut c_void,
) {
    if w.is_null() || u.is_null() || v.is_null() || ctx.is_null() {
        return;
    }
    let Some(ctx) = (unsafe { EcContext::as_ref(ctx) }) else {
        return;
    };
    if ctx.model() == CurveModel::Montgomery {
        return;
    }
    let Some(left) =
        (unsafe { LocalPoint::as_ref(u) }).and_then(|point| point_value_from_handle(point, ctx))
    else {
        return;
    };
    let Some(right) =
        (unsafe { LocalPoint::as_ref(v) }).and_then(|point| point_value_from_handle(point, ctx))
    else {
        return;
    };
    let result = match ctx.model() {
        CurveModel::Edwards => edwards_add(left, point_neg(right, ctx), ctx),
        _ => weier_add(left, point_neg(right, ctx), ctx),
    };
    let Some(result) = result else {
        return;
    };
    if let Some(dest) = unsafe { LocalPoint::as_mut(w) } {
        write_point_value(dest, result, false);
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_mul(
    w: *mut c_void,
    n: *mut gcry_mpi,
    u: *mut c_void,
    ctx: *mut c_void,
) {
    if w.is_null() || u.is_null() || ctx.is_null() {
        return;
    }
    let Some(ctx) = (unsafe { EcContext::as_ref(ctx) }) else {
        return;
    };
    let Some(dest) = (unsafe { LocalPoint::as_mut(w) }) else {
        return;
    };
    let Some(source) = (unsafe { LocalPoint::as_ref(u) }) else {
        return;
    };
    let secure = point_secure(source)
        || unsafe { gcry_mpi::as_ref(n) }
            .is_some_and(|mpi| mpi.secure || mpi.secret_sensitive);

    match ctx.model() {
        CurveModel::Montgomery => {
            let Some(point) = point_value_from_handle(source, ctx) else {
                return;
            };
            let PointValue::Affine(point) = point else {
                return;
            };
            let Some(scalar) = scalar_from_mpi_for_curve(n, ctx) else {
                return;
            };
            let Some(x) = montgomery_ladder(&scalar, &point.x, ctx) else {
                return;
            };
            write_point_value(
                dest,
                PointValue::Affine(AffinePoint {
                    x,
                    y: Mpz::from_ui(0),
                }),
                secure,
            );
        }
        _ => {
            let Some(base) = point_value_from_handle(source, ctx) else {
                return;
            };
            let Some(scalar) = scalar_from_mpi_for_curve(n, ctx) else {
                return;
            };
            let Some(result) = scalar_mul_affine(base, &scalar, ctx) else {
                return;
            };
            write_point_value(dest, result, secure);
        }
    }
}

#[no_mangle]
pub extern "C" fn gcry_mpi_ec_curve_point(w: *mut c_void, ctx: *mut c_void) -> c_int {
    if w.is_null() || ctx.is_null() {
        return 0;
    }
    let Some(ctx) = (unsafe { EcContext::as_ref(ctx) }) else {
        return 0;
    };
    let Some(point) = (unsafe { LocalPoint::as_ref(w) }) else {
        return 0;
    };
    point_value_from_handle(point, ctx).is_some_and(|value| ensure_point_on_curve(&value, ctx))
        as c_int
}
