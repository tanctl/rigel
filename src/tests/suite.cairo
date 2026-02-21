use core::array::{Array, ArrayTrait};
use core::ec::{EcPoint, EcStateTrait, NonZeroEcPoint};
use core::integer::u256;
use core::option::OptionTrait;
use core::poseidon::poseidon_hash_span;
use core::result::Result;
use core::traits::{Into, TryInto};

use crate::advanced::one_out_of_many::{
    PedersenOneOutOfManyProof,
    PedersenOneOutOfManyStatement,
    verify_pedersen_one_out_of_many,
    verify_pedersen_one_out_of_many_bytes,
};
use crate::advanced::ring::{RingProof, RingStatement, verify_ring, verify_ring_bytes};
use crate::composition::{
    AndInstance,
    OrInstance,
    fold_composition_labels,
    verify_and,
    verify_and_bytes,
    verify_or,
    verify_or_bytes,
    batch_verify_schnorr,
    batch_verify_schnorr_bytes,
    batch_verify_dlog,
    batch_verify_dlog_bytes,
    batch_verify_chaum_ped,
    batch_verify_chaum_ped_bytes,
    batch_verify_okamoto,
    batch_verify_okamoto_bytes,
    batch_verify_pedersen,
    batch_verify_pedersen_bytes,
    batch_verify_pedersen_eq,
    batch_verify_pedersen_eq_bytes,
    batch_verify_pedersen_rerand,
    batch_verify_pedersen_rerand_bytes,
};
use crate::core::canonical::{TAG_DLOG, TAG_SCHNORR};
use crate::core::curve::{generator as generator_opt, point_coordinates, validate_point};
use crate::core::errors::VerifyError;
use crate::core::challenge::{compute_challenge, compute_challenge_checked};
use crate::core::scalar::{mul_mod_order, order_u256, reduce_mod_order, sub_mod_order};
use crate::core::sigma::derive_challenge;
use crate::core::transcript::{
    CURVE_ID_STARK,
    PROTOCOL_AND,
    PROTOCOL_OR,
    transcript_append_felt,
    transcript_append_point,
    transcript_append_span,
    transcript_challenge,
    transcript_new_and,
    transcript_new_or,
};
use crate::protocols::atomic::dlog::{verify_dlog, verify_dlog_short};
use crate::protocols::atomic::chaum_pedersen::verify_chaum_ped;
use crate::protocols::atomic::okamoto::verify_okamoto;
use crate::protocols::atomic::schnorr::{verify_schnorr, verify_schnorr_short};
use crate::protocols::pedersen::bases::pedersen_h as pedersen_h_opt;
use crate::protocols::pedersen::equality::verify_pedersen_eq;
use crate::protocols::pedersen::opening::{verify_pedersen_opening, verify_pedersen_opening_short};
use crate::protocols::pedersen::rerand::verify_pedersen_rerand;
use crate::protocols::types::{
    ChaumPedProof,
    ChaumPedStatement,
    DLogProof,
    DLogStatement,
    OkamotoProof,
    OkamotoStatement,
    PedersenEqProof,
    PedersenEqStatement,
    PedersenProof,
    PedersenRerandProof,
    PedersenRerandStatement,
    PedersenStatement,
    SchnorrProof,
    SchnorrStatement,
    SigmaProof,
    SigmaStatement,
};

fn assert_ok(result: Result<(), VerifyError>, err: felt252) {
    match result {
        Result::Ok(_) => {},
        Result::Err(_) => {
            core::panic_with_felt252(err);
        },
    }
}

fn assert_err(result: Result<(), VerifyError>, err: felt252) {
    match result {
        Result::Ok(_) => {
            core::panic_with_felt252(err);
        },
        Result::Err(_) => {},
    }
}

fn assert_err_exact(
    result: Result<(), VerifyError>, expected: VerifyError, err: felt252,
) {
    match result {
        Result::Ok(_) => {
            core::panic_with_felt252(err);
        },
        Result::Err(actual) => {
            if actual != expected {
                core::panic_with_felt252(err);
            }
        },
    }
}

fn point(x: felt252, y: felt252) -> NonZeroEcPoint {
    validate_point(x, y).unwrap()
}

fn generator() -> NonZeroEcPoint {
    let Some(g) = generator_opt() else {
        core::panic_with_felt252('GEN_INVALID');
    };
    g
}

fn pedersen_h() -> NonZeroEcPoint {
    let Some(h) = pedersen_h_opt() else {
        core::panic_with_felt252('H_INVALID');
    };
    h
}

fn add_mod_order(a: felt252, b: felt252) -> felt252 {
    let order = order_u256();
    let a_u256: u256 = a.into();
    let b_u256: u256 = b.into();
    let sum = a_u256 + b_u256;
    let reduced = if sum >= order { sum - order } else { sum };
    reduced.try_into().unwrap()
}

fn mul_point(scalar: felt252, base: NonZeroEcPoint) -> NonZeroEcPoint {
    let mut state = EcStateTrait::init();
    state.add_mul(scalar, base);
    let point: EcPoint = state.finalize();
    point.try_into().unwrap()
}

fn add_points(a: NonZeroEcPoint, b: NonZeroEcPoint) -> NonZeroEcPoint {
    let mut state = EcStateTrait::init();
    state.add(a);
    state.add(b);
    let point: EcPoint = state.finalize();
    point.try_into().unwrap()
}

fn ctx(tag: felt252) -> Array<felt252> {
    let mut out = ArrayTrait::new();
    out.append(20260210);
    out.append(tag);
    out
}

fn append_fixture_point_be64(ref out: Array<u8>) {
    // x coordinate
    out.append(7);
    out.append(136);
    out.append(67);
    out.append(93);
    out.append(97);
    out.append(4);
    out.append(109);
    out.append(62);
    out.append(236);
    out.append(84);
    out.append(215);
    out.append(125);
    out.append(37);
    out.append(189);
    out.append(25);
    out.append(69);
    out.append(37);
    out.append(244);
    out.append(250);
    out.append(38);
    out.append(235);
    out.append(230);
    out.append(87);
    out.append(85);
    out.append(54);
    out.append(188);
    out.append(111);
    out.append(101);
    out.append(102);
    out.append(86);
    out.append(183);
    out.append(76);
    // y coordinate
    out.append(1);
    out.append(57);
    out.append(38);
    out.append(56);
    out.append(107);
    out.append(158);
    out.append(94);
    out.append(144);
    out.append(140);
    out.append(53);
    out.append(149);
    out.append(25);
    out.append(234);
    out.append(166);
    out.append(140);
    out.append(68);
    out.append(162);
    out.append(67);
    out.append(15);
    out.append(75);
    out.append(76);
    out.append(165);
    out.append(208);
    out.append(219);
    out.append(220);
    out.append(180);
    out.append(35);
    out.append(31);
    out.append(3);
    out.append(30);
    out.append(177);
    out.append(139);
}

fn append_scalar_be32_last_byte(ref out: Array<u8>, last_byte: u8) {
    let mut i: u32 = 0;
    loop {
        if i >= 31 {
            break;
        }
        out.append(0);
        i += 1;
    }
    out.append(last_byte);
}

fn append_u256_be_fixed(ref out: Array<u8>, value: u256, bytes: u32) {
    if bytes == 0 {
        return;
    }
    let base: u256 = 256_u32.into();
    let base_nz: NonZero<u256> = base.try_into().unwrap();
    let (q, r) = DivRem::div_rem(value, base_nz);
    append_u256_be_fixed(ref out, q, bytes - 1);
    let b: u8 = r.try_into().unwrap();
    out.append(b);
}

fn append_scalar_be32(ref out: Array<u8>, scalar: felt252) {
    let scalar_u256: u256 = scalar.into();
    append_u256_be_fixed(ref out, scalar_u256, 32);
}

fn append_point_be64(ref out: Array<u8>, p: NonZeroEcPoint) {
    let (x, y) = point_coordinates(p);
    append_scalar_be32(ref out, x);
    append_scalar_be32(ref out, y);
}

#[test]
fn challenge_helper_matches_formula_and_checked() {
    let g = generator();
    let h = pedersen_h();

    let mut commitments = ArrayTrait::new();
    commitments.append(g);
    commitments.append(h);

    let mut context = ArrayTrait::new();
    context.append(20260223);
    context.append(71);

    let mut label_idx: u32 = 1;
    let mut statement_label: felt252 = label_idx.into();
    let mut challenge = compute_challenge(
        PROTOCOL_OR, statement_label, commitments.span(), context.span()
    );
    loop {
        if challenge != 0 {
            break;
        }
        label_idx += 1;
        if label_idx > 64 {
            core::panic_with_felt252('ZERO_CHALLENGE_LOOP');
        }
        statement_label = label_idx.into();
        challenge = compute_challenge(
            PROTOCOL_OR, statement_label, commitments.span(), context.span()
        );
    }

    let checked = compute_challenge_checked(
        PROTOCOL_OR, statement_label, commitments.span(), context.span()
    ).unwrap();
    if checked != challenge {
        core::panic_with_felt252('CHECKED_MISMATCH');
    }

    let mut manual = ArrayTrait::new();
    manual.append(PROTOCOL_OR);
    manual.append(CURVE_ID_STARK);
    manual.append(statement_label);
    let (gx, gy) = point_coordinates(g);
    manual.append(gx);
    manual.append(gy);
    let (hx, hy) = point_coordinates(h);
    manual.append(hx);
    manual.append(hy);
    manual.append_span(context.span());
    let expected = reduce_mod_order(poseidon_hash_span(manual.span()));
    if expected != challenge {
        core::panic_with_felt252('CHALLENGE_FORMULA');
    }
}

#[test]
fn external_vector_schnorr() {
    let public_key = point(
        3406946075390113347849186141614382943859026331139362801098460541807050012492,
        553286918727390295085862184332748643124765280169853477022816811418017247627,
    );
    let commitment = point(
        3285470181182513595299391888669018264373825695633626141263541088056464172983,
        407217118062758744964593760322705378299439026911040607736478266570367095223,
    );
    let response = 980221561379037743582031123278765752501810743681454087641714869757153182253;
    assert_ok(
        verify_schnorr(public_key, commitment, response, ctx(1).span()),
        'SCHNORR_FAIL',
    );
}

#[test]
fn external_vector_dlog() {
    let base = point(
        262578095662180838419669744841577391006900930438465299949309013509530449546,
        1803932398273292515046854939238941106017389255947930720851306443211978480491,
    );
    let public_key = point(
        569462207826592362018153934036028354211796431003364602513934710568917589279,
        1922545574614225791348787306996554510490628143833526907291787213251497526808,
    );
    let commitment = point(
        3591767385952792592442937923272085952947195013050436580637635255293712480043,
        2897430355311964852232912338349758016903570398252121932074461416797119759186,
    );
    let response = 832926995832538190254957075557328064736889282315376513040882738536214882189;
    assert_ok(
        verify_dlog(base, public_key, commitment, response, ctx(10).span()),
        'DLOG_FAIL',
    );
}

#[test]
fn external_vector_pedersen_opening() {
    let value_base = generator();
    let blinding_base = pedersen_h();
    let commitment = point(
        2406464085388195907644456968194723994194023855928604139983631013285293704834,
        820890515793216674554770252864015243903211557251169973197593889081243413428,
    );
    let nonce_commitment = point(
        729370830685404557863230945977597410603696619285627101711509882983645341654,
        2226200593606392991968897121405087077841463654931010981993329606473237719994,
    );
    let response_value = 3293210451043617578225605606582683760457482467865411817175382627999916799593;
    let response_blinding = 3542215588612812957767947719149326057980037134423250458332957041557608366547;
    assert_ok(
        verify_pedersen_opening(
            value_base,
            blinding_base,
            commitment,
            nonce_commitment,
            response_value,
            response_blinding,
            ctx(4).span(),
        ),
        'PEDERSEN_FAIL',
    );
}

#[test]
fn external_vector_chaum_pedersen() {
    let y1 = point(
        875940955200611947500760302054417515671876219465574517800446702396947535610,
        2976950011013311701273347535189853905279003536832852550673682997603920566673,
    );
    let y2 = point(
        2427415865029885740268687481536038875021262463326156464620088070830526831966,
        349045561797108842091684158634842966673413985127162674878147907880788923817,
    );
    let h = point(
        2422551216303013704344383652704059037840477723838376114986685605679710188093,
        2102423762283828492081972873116626073571791820212167684978746754419159853215,
    );
    let r1 = point(
        1414904107774701420161054128842762567969139319263736734867498960113151564766,
        3337252540928200396650014175361215244917634305439052419173253778806545007479,
    );
    let r2 = point(
        2306515873013420758036842943339734903947611631888760859325177796300894523849,
        174937397698465542442945550651598137280726540224841516351599523779780293708,
    );
    let response = 2687933560271562160270007857176716538503263860486553200091174062685834328778;
    assert_ok(
        verify_chaum_ped(y1, y2, h, r1, r2, response, ctx(52).span()),
        'CHAUM_PED_FAIL',
    );
}

#[test]
fn external_vector_okamoto() {
    let mut bases = ArrayTrait::new();
    bases.append(point(
        874739451078007766457464989774322083649278607533249481151382481072868806602,
        152666792071518830868575557812948353041420400780739481342941381225525861407,
    ));
    bases.append(point(
        262578095662180838419669744841577391006900930438465299949309013509530449546,
        1803932398273292515046854939238941106017389255947930720851306443211978480491,
    ));
    let y = point(
        2579057112593141767198642338855766057442462951835749075848135536180492619571,
        45780820797070149200967404218290679371016413533175028942725863370457836519,
    );
    let commitment = point(
        2831455120073493803789846699892284372964851317918011275449184845732855626755,
        1098759493643404166928078852443639428476790131629986266017480471387372366606,
    );
    let mut responses = ArrayTrait::new();
    responses.append(2738619047461456045358725303612683457662585422733414968042534627136347605630);
    responses.append(2983331938724482472529107889774660998146152613925432449497395868546351877059);
    assert_ok(
        verify_okamoto(
            bases.span(), y, commitment, responses.span(), ctx(53).span(),
        ),
        'OKAMOTO_FAIL',
    );
}

#[test]
fn external_vector_pedersen_eq() {
    let value_base1 = point(
        874739451078007766457464989774322083649278607533249481151382481072868806602,
        152666792071518830868575557812948353041420400780739481342941381225525861407,
    );
    let blinding_base1 = point(
        262578095662180838419669744841577391006900930438465299949309013509530449546,
        1803932398273292515046854939238941106017389255947930720851306443211978480491,
    );
    let commitment1 = point(
        3247883030263344698780174711645203428872093343719944750690438705625817982281,
        882400353686098188644133448617885765549987670895862008888140410654505314104,
    );
    let value_base2 = point(
        2147917197054818871619776655514917967724810669246777137580480562218260377891,
        1230877877612900447137853367185807507097371113825426166020962037710421986578,
    );
    let blinding_base2 = point(
        1202136698423557694813093187365538289510114755674493377326292303835379420777,
        290975096857175402782929780977515160233242252798575784124285991928647411936,
    );
    let commitment2 = point(
        3596308391988276563196182753608561209156849605879181899672896336337683355933,
        1700489388918177413949516622350899665511159546524522680537099558978141010942,
    );
    let nonce_commitment1 = point(
        2612781210506929726589695265522114147160910039374556967550959529408147566565,
        2282282984902398243240239646783783383532140394778300457594823948750845220998,
    );
    let nonce_commitment2 = point(
        703613924518593262920956791015599959703444474127388162870281915939289324006,
        1194444540531624025840453877506135470165857686877635545888536438311981634227,
    );
    let response_value = 2311415487950375336372981694768368676084380808940535441905850751353279996911;
    let response_blinding1 = 1064880009930846742703780702818674083202086881487097125175743377163884276326;
    let response_blinding2 = 3436847320577449362731902493964049595846536705749746297599715460859001421324;
    assert_ok(
        verify_pedersen_eq(
            value_base1,
            blinding_base1,
            commitment1,
            value_base2,
            blinding_base2,
            commitment2,
            nonce_commitment1,
            nonce_commitment2,
            response_value,
            response_blinding1,
            response_blinding2,
            ctx(55).span(),
        ),
        'PEDERSEN_EQ_FAIL',
    );
}

#[test]
fn external_vector_pedersen_rerand() {
    let rerand_base = point(
        262578095662180838419669744841577391006900930438465299949309013509530449546,
        1803932398273292515046854939238941106017389255947930720851306443211978480491,
    );
    let commitment_from = point(
        3216678424807850046385059354899847884811168715238289281485807193281403446746,
        3303453297268932199331925792389690819687181421997118714465741145231000092497,
    );
    let commitment_to = point(
        1009827069098377038542883207033178796832602596606273820046634869239197632432,
        1042672510176970678469424478629616170533654488147608446908723975711785849014,
    );
    let nonce_commitment = point(
        3141059115078535002181215008891926431827068233840792461122944949107688425755,
        3122883615010715736688409167477470323998597034443626744917097243436472755889,
    );
    let response = 3217491545549239860258383019804051819954844465183914376485225815204241322680;
    assert_ok(
        verify_pedersen_rerand(
            rerand_base,
            commitment_from,
            commitment_to,
            nonce_commitment,
            response,
            ctx(56).span(),
        ),
        'PEDERSEN_RERAND_FAIL',
    );
}

#[test]
fn external_vector_ring() {
    let mut keys = ArrayTrait::new();
    keys.append(point(
        1839793652349538280924927302501143912227271479439798783640887258675143576352,
        3564972295958783757568195431080951091358810058262272733141798511604612925062,
    ));
    keys.append(point(
        3406946075390113347849186141614382943859026331139362801098460541807050012492,
        553286918727390295085862184332748643124765280169853477022816811418017247627,
    ));
    let statement = RingStatement { public_keys: keys.span() };

    let mut commitments = ArrayTrait::new();
    commitments.append(point(
        3285470181182513595299391888669018264373825695633626141263541088056464172983,
        407217118062758744964593760322705378299439026911040607736478266570367095223,
    ));
    commitments.append(point(
        320701079910027581516523363326206993828482289921925795495069010139755848876,
        86111107131508518143460629642697049066317241128886286728078858604316168805,
    ));

    let mut challenges = ArrayTrait::new();
    challenges.append(947888622013788723423481396052728153245010988978174588437823694650367665181);
    challenges.append(5);

    let mut responses = ArrayTrait::new();
    responses.append(2843665866041366170270444188158184459735032966934523765313471083951102995550);
    responses.append(9);

    let proof = RingProof {
        commitments: commitments.span(),
        challenges: challenges.span(),
        responses: responses.span(),
    };
    assert_ok(verify_ring(statement, proof, ctx(9).span()), 'RING_FAIL');
}

#[test]
fn external_vector_one_out_of_many() {
    // deterministic vector generated with rigel-prover/src/advanced/one_out_of_many.rs (n = 4)
    let mut candidates = ArrayTrait::new();
    candidates.append(point(
        2160627205374934395380956586233141033062337805254667434369083337125562081092,
        1577639307602754121357933828774309650647842806240522608203196029615452252189,
    ));
    candidates.append(point(
        688059231895993503393662731696657904144882776974772956801291944945793775890,
        1492634175244891591920722330303630446955969892534557689539357334033062536459,
    ));
    candidates.append(point(
        2211915163744210002435633243413821242215448881253723035693454790810529931896,
        2324179063925462618380142842493191116561516653528018059960577508489459973285,
    ));
    candidates.append(point(
        2632570937868459737194056246470786486064311588614278376176503842473092555303,
        2672577973686876358347329972784495798169567660636479387718554549629893437946,
    ));
    let statement = PedersenOneOutOfManyStatement {
        commitment: point(
            2272198053618338088702170918820390142952883076121028600905991286215320371476,
            2418264294394625044103209679731488427941660910334703059558925258640815527255,
        ),
        candidates: candidates.span(),
    };

    let mut cl = ArrayTrait::new();
    cl.append(point(
        2924986934744762571054446804708278631121015683339884621880489134472709397785,
        918612455047664532850788411529196969042246740759827192854789153687040452283,
    ));
    cl.append(point(
        1394764600578691351515150027755192017456670716736378679469709847358408405681,
        993923513799993350335179827311356026449816299713070291420669652897505365522,
    ));

    let mut ca = ArrayTrait::new();
    ca.append(point(
        2656722002228781342328456638458034935558215098022945463490702237709152865444,
        1354638087260819093710381167289660273573625507702361150158027524814875778047,
    ));
    ca.append(point(
        2685246300650203611428558340592618904636440065333204545647264102635434978334,
        365052481316703452528047519607017914270921744548212891303215986108592406302,
    ));

    let mut cb = ArrayTrait::new();
    cb.append(point(
        2721500546232546464974991232662992910402240732558986689842261997669949638357,
        563151408339597868479001573594207844508186522875449991071209876330935259469,
    ));
    cb.append(point(
        515492522440375074868350337789479205774127705279282594204136950074813535748,
        363659986726877864371441055870073175894778299130258278966685763364208390092,
    ));

    let mut cd = ArrayTrait::new();
    cd.append(point(
        859719120670166300661822538268420020824488589324401944943566557050131819116,
        1638899790931727376535395371991719641138285338531364898853295028564418541718,
    ));
    cd.append(point(
        1262926561160792424516715930656245834233943114675952852623712210282241309893,
        2806990145940615781031365622896258566477817448477116135384888477402615765323,
    ));

    let mut f = ArrayTrait::new();
    f.append(1222080134854082554712367245795835192146322899606499958025580352287330878287);
    f.append(341535211590750585315556614900923601720508457491243828693775517049996941626);

    let mut za = ArrayTrait::new();
    za.append(723644067084731134272229336566473004072888024361021196173249811939945491362);
    za.append(2850847597415058213666497000227057234480186080486672535411244916680218171855);

    let mut zb = ArrayTrait::new();
    zb.append(1607233087471699638719706284788147222227377365963223564708388541844733549953);
    zb.append(2664871579069005639998677317281634812881015849975825026836636346238042133943);

    let proof = PedersenOneOutOfManyProof {
        cl: cl.span(),
        ca: ca.span(),
        cb: cb.span(),
        cd: cd.span(),
        f: f.span(),
        za: za.span(),
        zb: zb.span(),
        zd: 2743146627415630096817715244782392291550194222069414556494853461580860400865,
    };
    assert_ok(
        verify_pedersen_one_out_of_many(statement, proof, ctx(14).span()),
        'OOM_FAIL',
    );
}

#[test]
fn one_out_of_many_rejects_non_power_of_two_ring_size() {
    let mut candidates = ArrayTrait::new();
    candidates.append(point(
        3134539674415462804556755567595652649495910034406204671653394800061356416497,
        479158542193768852742921116298787299879860196619342149901094656398252806471,
    ));
    candidates.append(point(
        1694633356675200244992396799098670030114801704942825630237691680881066708998,
        1217649704361063936660721918028945109566640726114264422150637700371399093735,
    ));
    candidates.append(point(
        2108746274279092936816264532532893453455077142636697892280032099718700642651,
        1171511004350419758109088774480004486324774735023772568646647831479505722800,
    ));
    let statement = PedersenOneOutOfManyStatement {
        commitment: point(
            169845426980778147223659873209751779935175300973764289293028303708279538516,
            3207208758082118152706590905231865140731483738038625045255792378270321686166,
        ),
        candidates: candidates.span(),
    };

    let empty_points: Array<NonZeroEcPoint> = ArrayTrait::new();
    let empty_scalars: Array<felt252> = ArrayTrait::new();
    let proof = PedersenOneOutOfManyProof {
        cl: empty_points.span(),
        ca: empty_points.span(),
        cb: empty_points.span(),
        cd: empty_points.span(),
        f: empty_scalars.span(),
        za: empty_scalars.span(),
        zb: empty_scalars.span(),
        zd: 0,
    };
    assert_err_exact(
        verify_pedersen_one_out_of_many(statement, proof, ctx(17).span()),
        VerifyError::RingSizeMustBePowerOfTwo,
        'BAD_OOM_POW2',
    );
}

#[test]
fn one_out_of_many_rejects_mismatched_lengths() {
    let mut candidates = ArrayTrait::new();
    candidates.append(point(
        2160627205374934395380956586233141033062337805254667434369083337125562081092,
        1577639307602754121357933828774309650647842806240522608203196029615452252189,
    ));
    candidates.append(point(
        688059231895993503393662731696657904144882776974772956801291944945793775890,
        1492634175244891591920722330303630446955969892534557689539357334033062536459,
    ));
    candidates.append(point(
        2211915163744210002435633243413821242215448881253723035693454790810529931896,
        2324179063925462618380142842493191116561516653528018059960577508489459973285,
    ));
    candidates.append(point(
        2632570937868459737194056246470786486064311588614278376176503842473092555303,
        2672577973686876358347329972784495798169567660636479387718554549629893437946,
    ));
    let statement = PedersenOneOutOfManyStatement {
        commitment: point(
            2272198053618338088702170918820390142952883076121028600905991286215320371476,
            2418264294394625044103209679731488427941660910334703059558925258640815527255,
        ),
        candidates: candidates.span(),
    };

    let empty_points: Array<NonZeroEcPoint> = ArrayTrait::new();
    let empty_scalars: Array<felt252> = ArrayTrait::new();
    let proof = PedersenOneOutOfManyProof {
        cl: empty_points.span(),
        ca: empty_points.span(),
        cb: empty_points.span(),
        cd: empty_points.span(),
        f: empty_scalars.span(),
        za: empty_scalars.span(),
        zb: empty_scalars.span(),
        zd: 1,
    };

    assert_err(
        verify_pedersen_one_out_of_many(statement, proof, ctx(14).span()),
        'BAD_OOM_LEN',
    );
}

#[test]
fn one_out_of_many_rejects_tampered_scalar() {
    let mut candidates = ArrayTrait::new();
    candidates.append(point(
        2160627205374934395380956586233141033062337805254667434369083337125562081092,
        1577639307602754121357933828774309650647842806240522608203196029615452252189,
    ));
    candidates.append(point(
        688059231895993503393662731696657904144882776974772956801291944945793775890,
        1492634175244891591920722330303630446955969892534557689539357334033062536459,
    ));
    candidates.append(point(
        2211915163744210002435633243413821242215448881253723035693454790810529931896,
        2324179063925462618380142842493191116561516653528018059960577508489459973285,
    ));
    candidates.append(point(
        2632570937868459737194056246470786486064311588614278376176503842473092555303,
        2672577973686876358347329972784495798169567660636479387718554549629893437946,
    ));
    let statement = PedersenOneOutOfManyStatement {
        commitment: point(
            2272198053618338088702170918820390142952883076121028600905991286215320371476,
            2418264294394625044103209679731488427941660910334703059558925258640815527255,
        ),
        candidates: candidates.span(),
    };

    let mut cl = ArrayTrait::new();
    cl.append(point(
        2924986934744762571054446804708278631121015683339884621880489134472709397785,
        918612455047664532850788411529196969042246740759827192854789153687040452283,
    ));
    cl.append(point(
        1394764600578691351515150027755192017456670716736378679469709847358408405681,
        993923513799993350335179827311356026449816299713070291420669652897505365522,
    ));

    let mut ca = ArrayTrait::new();
    ca.append(point(
        2656722002228781342328456638458034935558215098022945463490702237709152865444,
        1354638087260819093710381167289660273573625507702361150158027524814875778047,
    ));
    ca.append(point(
        2685246300650203611428558340592618904636440065333204545647264102635434978334,
        365052481316703452528047519607017914270921744548212891303215986108592406302,
    ));

    let mut cb = ArrayTrait::new();
    cb.append(point(
        2721500546232546464974991232662992910402240732558986689842261997669949638357,
        563151408339597868479001573594207844508186522875449991071209876330935259469,
    ));
    cb.append(point(
        515492522440375074868350337789479205774127705279282594204136950074813535748,
        363659986726877864371441055870073175894778299130258278966685763364208390092,
    ));

    let mut cd = ArrayTrait::new();
    cd.append(point(
        859719120670166300661822538268420020824488589324401944943566557050131819116,
        1638899790931727376535395371991719641138285338531364898853295028564418541718,
    ));
    cd.append(point(
        1262926561160792424516715930656245834233943114675952852623712210282241309893,
        2806990145940615781031365622896258566477817448477116135384888477402615765323,
    ));

    let mut f = ArrayTrait::new();
    f.append(add_mod_order(
        1222080134854082554712367245795835192146322899606499958025580352287330878287,
        1,
    ));
    f.append(341535211590750585315556614900923601720508457491243828693775517049996941626);

    let mut za = ArrayTrait::new();
    za.append(723644067084731134272229336566473004072888024361021196173249811939945491362);
    za.append(2850847597415058213666497000227057234480186080486672535411244916680218171855);

    let mut zb = ArrayTrait::new();
    zb.append(1607233087471699638719706284788147222227377365963223564708388541844733549953);
    zb.append(2664871579069005639998677317281634812881015849975825026836636346238042133943);

    let proof = PedersenOneOutOfManyProof {
        cl: cl.span(),
        ca: ca.span(),
        cb: cb.span(),
        cd: cd.span(),
        f: f.span(),
        za: za.span(),
        zb: zb.span(),
        zd: 2743146627415630096817715244782392291550194222069414556494853461580860400865,
    };

    assert_err(
        verify_pedersen_one_out_of_many(statement, proof, ctx(14).span()),
        'BAD_OOM_SCALAR',
    );
}

#[test]
fn one_out_of_many_n1_valid_and_bytes() {
    let commitment = point(
        3406946075390113347849186141614382943859026331139362801098460541807050012492,
        553286918727390295085862184332748643124765280169853477022816811418017247627,
    );

    let mut candidates = ArrayTrait::new();
    candidates.append(commitment);
    let statement = PedersenOneOutOfManyStatement {
        commitment,
        candidates: candidates.span(),
    };

    let empty_points: Array<NonZeroEcPoint> = ArrayTrait::new();
    let empty_scalars: Array<felt252> = ArrayTrait::new();
    let proof = PedersenOneOutOfManyProof {
        cl: empty_points.span(),
        ca: empty_points.span(),
        cb: empty_points.span(),
        cd: empty_points.span(),
        f: empty_scalars.span(),
        za: empty_scalars.span(),
        zb: empty_scalars.span(),
        zd: 0,
    };

    assert_ok(
        verify_pedersen_one_out_of_many(statement, proof, ctx(15).span()),
        'OOM_N1_FAIL',
    );

    let mut commitment_bytes: Array<u8> = ArrayTrait::new();
    append_fixture_point_be64(ref commitment_bytes);
    let mut candidates_bytes: Array<u8> = ArrayTrait::new();
    append_fixture_point_be64(ref candidates_bytes);
    let proof_commitments: Array<u8> = ArrayTrait::new();
    let mut proof_scalars: Array<u8> = ArrayTrait::new();
    append_scalar_be32_last_byte(ref proof_scalars, 0);

    assert_ok(
        verify_pedersen_one_out_of_many_bytes(
            commitment_bytes.span(),
            candidates_bytes.span(),
            proof_commitments.span(),
            proof_scalars.span(),
            ctx(15).span(),
        ),
        'OOM_N1_BYTES_FAIL',
    );
}

#[test]
fn one_out_of_many_n1_rejects_bad_zd() {
    let commitment = point(
        3406946075390113347849186141614382943859026331139362801098460541807050012492,
        553286918727390295085862184332748643124765280169853477022816811418017247627,
    );

    let mut candidates = ArrayTrait::new();
    candidates.append(commitment);
    let statement = PedersenOneOutOfManyStatement {
        commitment,
        candidates: candidates.span(),
    };

    let empty_points: Array<NonZeroEcPoint> = ArrayTrait::new();
    let empty_scalars: Array<felt252> = ArrayTrait::new();
    let proof = PedersenOneOutOfManyProof {
        cl: empty_points.span(),
        ca: empty_points.span(),
        cb: empty_points.span(),
        cd: empty_points.span(),
        f: empty_scalars.span(),
        za: empty_scalars.span(),
        zb: empty_scalars.span(),
        zd: 1,
    };

    assert_err(
        verify_pedersen_one_out_of_many(statement, proof, ctx(16).span()),
        'BAD_OOM_N1',
    );

    let mut commitment_bytes: Array<u8> = ArrayTrait::new();
    append_fixture_point_be64(ref commitment_bytes);
    let mut candidates_bytes: Array<u8> = ArrayTrait::new();
    append_fixture_point_be64(ref candidates_bytes);
    let proof_commitments: Array<u8> = ArrayTrait::new();
    let mut bad_proof_scalars: Array<u8> = ArrayTrait::new();
    append_scalar_be32_last_byte(ref bad_proof_scalars, 1);

    assert_err(
        verify_pedersen_one_out_of_many_bytes(
            commitment_bytes.span(),
            candidates_bytes.span(),
            proof_commitments.span(),
            bad_proof_scalars.span(),
            ctx(16).span(),
        ),
        'BAD_OOM_N1_BYTES',
    );
}

#[test]
fn ring_rejects_mismatched_lengths() {
    let mut keys = ArrayTrait::new();
    keys.append(point(
        1839793652349538280924927302501143912227271479439798783640887258675143576352,
        3564972295958783757568195431080951091358810058262272733141798511604612925062,
    ));
    let statement = RingStatement { public_keys: keys.span() };

    let empty_points: Array<NonZeroEcPoint> = ArrayTrait::new();
    let empty_scalars: Array<felt252> = ArrayTrait::new();
    let proof = RingProof {
        commitments: empty_points.span(),
        challenges: empty_scalars.span(),
        responses: empty_scalars.span(),
    };
    assert_err(verify_ring(statement, proof, ctx(9).span()), 'BAD_RING_ACCEPTED');
}

#[test]
fn ring_rejects_challenge_sum_mismatch() {
    let mut keys = ArrayTrait::new();
    keys.append(point(
        1839793652349538280924927302501143912227271479439798783640887258675143576352,
        3564972295958783757568195431080951091358810058262272733141798511604612925062,
    ));
    keys.append(point(
        3406946075390113347849186141614382943859026331139362801098460541807050012492,
        553286918727390295085862184332748643124765280169853477022816811418017247627,
    ));
    let statement = RingStatement { public_keys: keys.span() };

    let mut commitments = ArrayTrait::new();
    commitments.append(point(
        3285470181182513595299391888669018264373825695633626141263541088056464172983,
        407217118062758744964593760322705378299439026911040607736478266570367095223,
    ));
    commitments.append(point(
        320701079910027581516523363326206993828482289921925795495069010139755848876,
        86111107131508518143460629642697049066317241128886286728078858604316168805,
    ));

    let challenge1 = 947888622013788723423481396052728153245010988978174588437823694650367665181;
    let challenge2 = 5;
    let mut challenges = ArrayTrait::new();
    challenges.append(add_mod_order(challenge1, 1));
    challenges.append(challenge2);

    let mut responses = ArrayTrait::new();
    responses.append(2843665866041366170270444188158184459735032966934523765313471083951102995550);
    responses.append(9);

    let proof = RingProof {
        commitments: commitments.span(),
        challenges: challenges.span(),
        responses: responses.span(),
    };
    assert_err_exact(
        verify_ring(statement, proof, ctx(44).span()),
        VerifyError::OrChallengeSumMismatch,
        'BAD_RING_SUM',
    );
}

#[test]
fn ring_rejects_sum_preserving_challenge_tamper() {
    let mut keys = ArrayTrait::new();
    keys.append(point(
        1839793652349538280924927302501143912227271479439798783640887258675143576352,
        3564972295958783757568195431080951091358810058262272733141798511604612925062,
    ));
    keys.append(point(
        3406946075390113347849186141614382943859026331139362801098460541807050012492,
        553286918727390295085862184332748643124765280169853477022816811418017247627,
    ));
    let statement = RingStatement { public_keys: keys.span() };

    let mut commitments = ArrayTrait::new();
    commitments.append(point(
        3285470181182513595299391888669018264373825695633626141263541088056464172983,
        407217118062758744964593760322705378299439026911040607736478266570367095223,
    ));
    commitments.append(point(
        320701079910027581516523363326206993828482289921925795495069010139755848876,
        86111107131508518143460629642697049066317241128886286728078858604316168805,
    ));

    let challenge1 = 947888622013788723423481396052728153245010988978174588437823694650367665181;
    let challenge2 = 5;
    let mut challenges = ArrayTrait::new();
    challenges.append(add_mod_order(challenge1, 1));
    challenges.append(sub_mod_order(challenge2, 1));

    let mut responses = ArrayTrait::new();
    responses.append(2843665866041366170270444188158184459735032966934523765313471083951102995550);
    responses.append(9);

    let proof = RingProof {
        commitments: commitments.span(),
        challenges: challenges.span(),
        responses: responses.span(),
    };
    assert_err_exact(
        verify_ring(statement, proof, ctx(9).span()),
        VerifyError::InvalidProof,
        'BAD_RING_BAL',
    );
}

#[test]
fn pedersen_h_not_generator() {
    let g = generator();
    let h = pedersen_h();
    let (gx, gy) = point_coordinates(g);
    let (hx, hy) = point_coordinates(h);
    if gx == hx && gy == hy {
        core::panic_with_felt252('BAD_PED_H');
    }
}

#[test]
fn external_vector_schnorr_short() {
    let public_key = point(
        3406946075390113347849186141614382943859026331139362801098460541807050012492,
        553286918727390295085862184332748643124765280169853477022816811418017247627,
    );
    let commitment = point(
        3285470181182513595299391888669018264373825695633626141263541088056464172983,
        407217118062758744964593760322705378299439026911040607736478266570367095223,
    );
    let response = 980221561379037743582031123278765752501810743681454087641714869757153182253;
    let statement = SigmaStatement::Schnorr(SchnorrStatement { public_key });
    let proof = SigmaProof::Schnorr(SchnorrProof { commitment, response });
    let challenge = derive_challenge(statement, proof, ctx(1).span()).unwrap();
    assert_ok(
        verify_schnorr_short(public_key, challenge, response, ctx(1).span()),
        'SCHNORR_SHORT_FAIL',
    );
}

#[test]
fn external_vector_dlog_short() {
    let base = point(
        262578095662180838419669744841577391006900930438465299949309013509530449546,
        1803932398273292515046854939238941106017389255947930720851306443211978480491,
    );
    let public_key = point(
        569462207826592362018153934036028354211796431003364602513934710568917589279,
        1922545574614225791348787306996554510490628143833526907291787213251497526808,
    );
    let commitment = point(
        3591767385952792592442937923272085952947195013050436580637635255293712480043,
        2897430355311964852232912338349758016903570398252121932074461416797119759186,
    );
    let response = 832926995832538190254957075557328064736889282315376513040882738536214882189;
    let statement = SigmaStatement::DLog(DLogStatement { base, public_key });
    let proof = SigmaProof::DLog(DLogProof { commitment, response });
    let challenge = derive_challenge(statement, proof, ctx(10).span()).unwrap();
    assert_ok(
        verify_dlog_short(base, public_key, challenge, response, ctx(10).span()),
        'DLOG_SHORT_FAIL',
    );
}

#[test]
fn external_vector_pedersen_short() {
    let value_base = generator();
    let blinding_base = pedersen_h();
    let commitment = point(
        2406464085388195907644456968194723994194023855928604139983631013285293704834,
        820890515793216674554770252864015243903211557251169973197593889081243413428,
    );
    let nonce_commitment = point(
        729370830685404557863230945977597410603696619285627101711509882983645341654,
        2226200593606392991968897121405087077841463654931010981993329606473237719994,
    );
    let response_value = 3293210451043617578225605606582683760457482467865411817175382627999916799593;
    let response_blinding = 3542215588612812957767947719149326057980037134423250458332957041557608366547;
    let statement = SigmaStatement::Pedersen(PedersenStatement {
        value_base,
        blinding_base,
        commitment,
    });
    let proof = SigmaProof::Pedersen(PedersenProof {
        nonce_commitment,
        response_value,
        response_blinding,
    });
    let challenge = derive_challenge(statement, proof, ctx(4).span()).unwrap();
    assert_ok(
        verify_pedersen_opening_short(
            value_base,
            blinding_base,
            commitment,
            challenge,
            response_value,
            response_blinding,
            ctx(4).span(),
        ),
        'PEDERSEN_SHORT_FAIL',
    );
}

#[test]
fn and_composition_validates_shared_challenge() {
    let g = generator();
    let base = pedersen_h();
    let x1: felt252 = 7;
    let x2: felt252 = 11;
    let k1: felt252 = 13;
    let k2: felt252 = 17;

    let public_key1 = mul_point(x1, g);
    let public_key2 = mul_point(x2, base);
    let commitment1 = mul_point(k1, g);
    let commitment2 = mul_point(k2, base);

    let stmt1 = SigmaStatement::Schnorr(SchnorrStatement { public_key: public_key1 });
    let stmt2 = SigmaStatement::DLog(DLogStatement { base, public_key: public_key2 });

    let mut labels = ArrayTrait::new();
    labels.append(crate::core::sigma::statement_label(stmt1));
    labels.append(crate::core::sigma::statement_label(stmt2));
    let composition_label = fold_composition_labels(PROTOCOL_AND, labels.span()).unwrap();

    let mut transcript = transcript_new_and();
    transcript_append_felt(ref transcript, composition_label);
    transcript_append_point(ref transcript, commitment1);
    transcript_append_point(ref transcript, commitment2);
    transcript_append_span(ref transcript, ctx(42).span());
    let challenge = transcript_challenge(@transcript).unwrap();

    let response1 = add_mod_order(k1, mul_mod_order(challenge, x1));
    let response2 = add_mod_order(k2, mul_mod_order(challenge, x2));

    let mut instances = ArrayTrait::new();
    instances.append(AndInstance {
        statement: stmt1,
        proof: SigmaProof::Schnorr(SchnorrProof { commitment: commitment1, response: response1 }),
    });
    instances.append(AndInstance {
        statement: stmt2,
        proof: SigmaProof::DLog(DLogProof { commitment: commitment2, response: response2 }),
    });

    assert_ok(verify_and(instances.span(), ctx(42).span()), 'AND_FAIL');
}

#[test]
fn or_composition_validates_challenge_sum() {
    let g = generator();
    let base = pedersen_h();
    let x1: felt252 = 7;
    let x2: felt252 = 11;
    let k1: felt252 = 13;
    let k2: felt252 = 17;
    let c1: felt252 = 5;

    let public_key1 = mul_point(x1, g);
    let public_key2 = mul_point(x2, base);
    let commitment1 = mul_point(k1, g);
    let commitment2 = mul_point(k2, base);

    let stmt1 = SigmaStatement::Schnorr(SchnorrStatement { public_key: public_key1 });
    let stmt2 = SigmaStatement::DLog(DLogStatement { base, public_key: public_key2 });

    let mut labels = ArrayTrait::new();
    labels.append(crate::core::sigma::statement_label(stmt1));
    labels.append(crate::core::sigma::statement_label(stmt2));
    let composition_label = fold_composition_labels(PROTOCOL_OR, labels.span()).unwrap();

    let mut transcript = transcript_new_or();
    transcript_append_felt(ref transcript, composition_label);
    transcript_append_point(ref transcript, commitment1);
    transcript_append_point(ref transcript, commitment2);
    transcript_append_span(ref transcript, ctx(43).span());
    let global_challenge = transcript_challenge(@transcript).unwrap();
    let c2 = sub_mod_order(global_challenge, c1);

    let response1 = add_mod_order(k1, mul_mod_order(c1, x1));
    let response2 = add_mod_order(k2, mul_mod_order(c2, x2));

    let mut instances = ArrayTrait::new();
    instances.append(OrInstance {
        statement: stmt1,
        proof: SigmaProof::Schnorr(SchnorrProof { commitment: commitment1, response: response1 }),
        challenge: c1,
    });
    instances.append(OrInstance {
        statement: stmt2,
        proof: SigmaProof::DLog(DLogProof { commitment: commitment2, response: response2 }),
        challenge: c2,
    });
    assert_ok(verify_or(instances.span(), ctx(43).span()), 'OR_FAIL');

    let mut bad_instances = ArrayTrait::new();
    bad_instances.append(OrInstance {
        statement: stmt1,
        proof: SigmaProof::Schnorr(SchnorrProof { commitment: commitment1, response: response1 }),
        challenge: add_mod_order(c1, 1),
    });
    bad_instances.append(OrInstance {
        statement: stmt2,
        proof: SigmaProof::DLog(DLogProof { commitment: commitment2, response: response2 }),
        challenge: c2,
    });
    assert_err_exact(
        verify_or(bad_instances.span(), ctx(43).span()),
        VerifyError::OrChallengeSumMismatch,
        'OR_BAD',
    );

    let mut balanced_bad_instances = ArrayTrait::new();
    balanced_bad_instances.append(OrInstance {
        statement: stmt1,
        proof: SigmaProof::Schnorr(SchnorrProof { commitment: commitment1, response: response1 }),
        challenge: add_mod_order(c1, 1),
    });
    balanced_bad_instances.append(OrInstance {
        statement: stmt2,
        proof: SigmaProof::DLog(DLogProof { commitment: commitment2, response: response2 }),
        challenge: sub_mod_order(c2, 1),
    });
    assert_err_exact(
        verify_or(balanced_bad_instances.span(), ctx(43).span()),
        VerifyError::InvalidProof,
        'OR_BAD_BAL',
    );
}

#[test]
fn and_composition_bytes_validates_shared_challenge() {
    let g = generator();
    let base = pedersen_h();
    let x1: felt252 = 7;
    let x2: felt252 = 11;
    let k1: felt252 = 13;
    let k2: felt252 = 17;

    let public_key1 = mul_point(x1, g);
    let public_key2 = mul_point(x2, base);
    let commitment1 = mul_point(k1, g);
    let commitment2 = mul_point(k2, base);

    let stmt1 = SigmaStatement::Schnorr(SchnorrStatement { public_key: public_key1 });
    let stmt2 = SigmaStatement::DLog(DLogStatement { base, public_key: public_key2 });

    let mut labels = ArrayTrait::new();
    labels.append(crate::core::sigma::statement_label(stmt1));
    labels.append(crate::core::sigma::statement_label(stmt2));
    let composition_label = fold_composition_labels(PROTOCOL_AND, labels.span()).unwrap();

    let mut transcript = transcript_new_and();
    transcript_append_felt(ref transcript, composition_label);
    transcript_append_point(ref transcript, commitment1);
    transcript_append_point(ref transcript, commitment2);
    transcript_append_span(ref transcript, ctx(142).span());
    let challenge = transcript_challenge(@transcript).unwrap();

    let response1 = add_mod_order(k1, mul_mod_order(challenge, x1));
    let response2 = add_mod_order(k2, mul_mod_order(challenge, x2));

    let mut instances_bytes: Array<u8> = ArrayTrait::new();
    append_scalar_be32(ref instances_bytes, TAG_SCHNORR);
    append_point_be64(ref instances_bytes, public_key1);
    append_point_be64(ref instances_bytes, commitment1);
    append_scalar_be32(ref instances_bytes, response1);

    append_scalar_be32(ref instances_bytes, TAG_DLOG);
    append_point_be64(ref instances_bytes, base);
    append_point_be64(ref instances_bytes, public_key2);
    append_point_be64(ref instances_bytes, commitment2);
    append_scalar_be32(ref instances_bytes, response2);

    assert_ok(verify_and_bytes(instances_bytes.span(), ctx(142).span()), 'AND_BYTES_FAIL');
}

#[test]
fn or_composition_bytes_validates_challenge_sum() {
    let g = generator();
    let base = pedersen_h();
    let x1: felt252 = 7;
    let x2: felt252 = 11;
    let k1: felt252 = 13;
    let k2: felt252 = 17;
    let c1: felt252 = 5;

    let public_key1 = mul_point(x1, g);
    let public_key2 = mul_point(x2, base);
    let commitment1 = mul_point(k1, g);
    let commitment2 = mul_point(k2, base);

    let stmt1 = SigmaStatement::Schnorr(SchnorrStatement { public_key: public_key1 });
    let stmt2 = SigmaStatement::DLog(DLogStatement { base, public_key: public_key2 });

    let mut labels = ArrayTrait::new();
    labels.append(crate::core::sigma::statement_label(stmt1));
    labels.append(crate::core::sigma::statement_label(stmt2));
    let composition_label = fold_composition_labels(PROTOCOL_OR, labels.span()).unwrap();

    let mut transcript = transcript_new_or();
    transcript_append_felt(ref transcript, composition_label);
    transcript_append_point(ref transcript, commitment1);
    transcript_append_point(ref transcript, commitment2);
    transcript_append_span(ref transcript, ctx(143).span());
    let global_challenge = transcript_challenge(@transcript).unwrap();
    let c2 = sub_mod_order(global_challenge, c1);

    let response1 = add_mod_order(k1, mul_mod_order(c1, x1));
    let response2 = add_mod_order(k2, mul_mod_order(c2, x2));

    let mut instances_bytes: Array<u8> = ArrayTrait::new();
    append_scalar_be32(ref instances_bytes, TAG_SCHNORR);
    append_point_be64(ref instances_bytes, public_key1);
    append_point_be64(ref instances_bytes, commitment1);
    append_scalar_be32(ref instances_bytes, response1);
    append_scalar_be32(ref instances_bytes, c1);

    append_scalar_be32(ref instances_bytes, TAG_DLOG);
    append_point_be64(ref instances_bytes, base);
    append_point_be64(ref instances_bytes, public_key2);
    append_point_be64(ref instances_bytes, commitment2);
    append_scalar_be32(ref instances_bytes, response2);
    append_scalar_be32(ref instances_bytes, c2);

    assert_ok(verify_or_bytes(instances_bytes.span(), ctx(143).span()), 'OR_BYTES_FAIL');
}

#[test]
fn and_composition_bytes_rejects_malformed_encoding() {
    let g = generator();
    let public_key = mul_point(7, g);
    let commitment = mul_point(9, g);

    let mut instances_bytes: Array<u8> = ArrayTrait::new();
    append_scalar_be32(ref instances_bytes, TAG_SCHNORR);
    append_point_be64(ref instances_bytes, public_key);
    append_point_be64(ref instances_bytes, commitment);
    append_u256_be_fixed(ref instances_bytes, 1_u256, 31);

    assert_err_exact(
        verify_and_bytes(instances_bytes.span(), ctx(211).span()),
        VerifyError::InvalidEncoding,
        'AND_BYTES_BADENC',
    );
}

#[test]
fn or_composition_bytes_rejects_malformed_encoding() {
    let g = generator();
    let public_key = mul_point(7, g);
    let commitment = mul_point(9, g);

    let mut instances_bytes: Array<u8> = ArrayTrait::new();
    append_scalar_be32(ref instances_bytes, TAG_SCHNORR);
    append_point_be64(ref instances_bytes, public_key);
    append_point_be64(ref instances_bytes, commitment);
    append_scalar_be32_last_byte(ref instances_bytes, 1);
    append_u256_be_fixed(ref instances_bytes, 1_u256, 31);

    assert_err_exact(
        verify_or_bytes(instances_bytes.span(), ctx(212).span()),
        VerifyError::InvalidEncoding,
        'OR_BYTES_BADENC',
    );
}

#[test]
fn ring_bytes_rejects_malformed_encoding() {
    let key = point(
        1839793652349538280924927302501143912227271479439798783640887258675143576352,
        3564972295958783757568195431080951091358810058262272733141798511604612925062,
    );
    let commitment = point(
        3285470181182513595299391888669018264373825695633626141263541088056464172983,
        407217118062758744964593760322705378299439026911040607736478266570367095223,
    );

    let mut keys_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref keys_bytes, key);

    let mut commitments_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref commitments_bytes, commitment);

    let mut challenges_bytes: Array<u8> = ArrayTrait::new();
    append_u256_be_fixed(ref challenges_bytes, 1_u256, 31);

    let mut responses_bytes: Array<u8> = ArrayTrait::new();
    append_scalar_be32_last_byte(ref responses_bytes, 1);

    assert_err_exact(
        verify_ring_bytes(
            keys_bytes.span(),
            commitments_bytes.span(),
            challenges_bytes.span(),
            responses_bytes.span(),
            ctx(213).span(),
        ),
        VerifyError::InvalidEncoding,
        'RING_BYTES_BADENC',
    );
}

#[test]
fn batch_schnorr_bytes_rejects_malformed_encoding() {
    let g = generator();
    let public_key = mul_point(7, g);
    let commitment = mul_point(9, g);

    let mut statements_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref statements_bytes, public_key);

    let mut proofs_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref proofs_bytes, commitment);
    append_u256_be_fixed(ref proofs_bytes, 1_u256, 31);

    assert_err_exact(
        batch_verify_schnorr_bytes(statements_bytes.span(), proofs_bytes.span(), ctx(214).span()),
        VerifyError::InvalidEncoding,
        'BATCH_S_BADENC',
    );
}

#[test]
fn batch_dlog_bytes_rejects_malformed_encoding() {
    let g = generator();
    let h = pedersen_h();
    let public_key = mul_point(7, g);
    let commitment = mul_point(9, h);

    let mut statements_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref statements_bytes, h);
    append_point_be64(ref statements_bytes, public_key);

    let mut proofs_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref proofs_bytes, commitment);
    append_u256_be_fixed(ref proofs_bytes, 1_u256, 31);

    assert_err_exact(
        batch_verify_dlog_bytes(statements_bytes.span(), proofs_bytes.span(), ctx(215).span()),
        VerifyError::InvalidEncoding,
        'BATCH_D_BADENC',
    );
}

#[test]
fn batch_chaum_ped_bytes_rejects_malformed_encoding() {
    let g = generator();
    let h = pedersen_h();
    let y1 = mul_point(7, g);
    let y2 = mul_point(7, h);
    let r1 = mul_point(9, g);
    let r2 = mul_point(9, h);

    let mut statements_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref statements_bytes, y1);
    append_point_be64(ref statements_bytes, y2);
    append_point_be64(ref statements_bytes, h);

    let mut proofs_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref proofs_bytes, r1);
    append_point_be64(ref proofs_bytes, r2);
    append_u256_be_fixed(ref proofs_bytes, 1_u256, 31);

    assert_err_exact(
        batch_verify_chaum_ped_bytes(
            statements_bytes.span(), proofs_bytes.span(), ctx(216).span(),
        ),
        VerifyError::InvalidEncoding,
        'BATCH_CP_BADENC',
    );
}

#[test]
fn batch_okamoto_bytes_rejects_malformed_encoding() {
    let g = generator();
    let y = mul_point(7, g);
    let commitment = mul_point(9, g);

    let mut statements_bytes: Array<u8> = ArrayTrait::new();
    append_scalar_be32_last_byte(ref statements_bytes, 1);
    append_point_be64(ref statements_bytes, g);
    append_point_be64(ref statements_bytes, y);

    let mut proofs_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref proofs_bytes, commitment);
    append_u256_be_fixed(ref proofs_bytes, 1_u256, 31);

    assert_err_exact(
        batch_verify_okamoto_bytes(
            statements_bytes.span(), proofs_bytes.span(), ctx(217).span(),
        ),
        VerifyError::InvalidEncoding,
        'BATCH_O_BADENC',
    );
}

#[test]
fn batch_pedersen_bytes_rejects_malformed_encoding() {
    let g = generator();
    let h = pedersen_h();
    let commitment = add_points(mul_point(7, g), mul_point(11, h));
    let nonce_commitment = add_points(mul_point(9, g), mul_point(13, h));

    let mut statements_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref statements_bytes, g);
    append_point_be64(ref statements_bytes, h);
    append_point_be64(ref statements_bytes, commitment);

    let mut proofs_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref proofs_bytes, nonce_commitment);
    append_scalar_be32_last_byte(ref proofs_bytes, 1);
    append_u256_be_fixed(ref proofs_bytes, 1_u256, 31);

    assert_err_exact(
        batch_verify_pedersen_bytes(
            statements_bytes.span(), proofs_bytes.span(), ctx(218).span(),
        ),
        VerifyError::InvalidEncoding,
        'BATCH_P_BADENC',
    );
}

#[test]
fn batch_pedersen_eq_bytes_rejects_malformed_encoding() {
    let g = generator();
    let h = pedersen_h();
    let commitment1 = add_points(mul_point(7, g), mul_point(11, h));
    let commitment2 = add_points(mul_point(7, h), mul_point(11, g));
    let nonce_commitment1 = add_points(mul_point(9, g), mul_point(13, h));
    let nonce_commitment2 = add_points(mul_point(9, h), mul_point(13, g));

    let mut statements_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref statements_bytes, g);
    append_point_be64(ref statements_bytes, h);
    append_point_be64(ref statements_bytes, commitment1);
    append_point_be64(ref statements_bytes, h);
    append_point_be64(ref statements_bytes, g);
    append_point_be64(ref statements_bytes, commitment2);

    let mut proofs_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref proofs_bytes, nonce_commitment1);
    append_point_be64(ref proofs_bytes, nonce_commitment2);
    append_scalar_be32_last_byte(ref proofs_bytes, 1);
    append_scalar_be32_last_byte(ref proofs_bytes, 2);
    append_u256_be_fixed(ref proofs_bytes, 1_u256, 31);

    assert_err_exact(
        batch_verify_pedersen_eq_bytes(
            statements_bytes.span(), proofs_bytes.span(), ctx(219).span(),
        ),
        VerifyError::InvalidEncoding,
        'BATCH_PE_BADENC',
    );
}

#[test]
fn batch_pedersen_rerand_bytes_rejects_malformed_encoding() {
    let g = generator();
    let h = pedersen_h();
    let commitment_from = add_points(mul_point(7, g), mul_point(11, h));
    let commitment_to = add_points(commitment_from, mul_point(5, h));
    let nonce_commitment = mul_point(9, h);

    let mut statements_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref statements_bytes, h);
    append_point_be64(ref statements_bytes, commitment_from);
    append_point_be64(ref statements_bytes, commitment_to);

    let mut proofs_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref proofs_bytes, nonce_commitment);
    append_u256_be_fixed(ref proofs_bytes, 1_u256, 31);

    assert_err_exact(
        batch_verify_pedersen_rerand_bytes(
            statements_bytes.span(), proofs_bytes.span(), ctx(220).span(),
        ),
        VerifyError::InvalidEncoding,
        'BATCH_PR_BADENC',
    );
}

#[test]
fn ring_bytes_external_vector() {
    let key1 = point(
        1839793652349538280924927302501143912227271479439798783640887258675143576352,
        3564972295958783757568195431080951091358810058262272733141798511604612925062,
    );
    let key2 = point(
        3406946075390113347849186141614382943859026331139362801098460541807050012492,
        553286918727390295085862184332748643124765280169853477022816811418017247627,
    );
    let commitment1 = point(
        3285470181182513595299391888669018264373825695633626141263541088056464172983,
        407217118062758744964593760322705378299439026911040607736478266570367095223,
    );
    let commitment2 = point(
        320701079910027581516523363326206993828482289921925795495069010139755848876,
        86111107131508518143460629642697049066317241128886286728078858604316168805,
    );
    let challenge1 = 947888622013788723423481396052728153245010988978174588437823694650367665181;
    let challenge2 = 5;
    let response1 = 2843665866041366170270444188158184459735032966934523765313471083951102995550;
    let response2 = 9;

    let mut keys_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref keys_bytes, key1);
    append_point_be64(ref keys_bytes, key2);

    let mut commitments_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref commitments_bytes, commitment1);
    append_point_be64(ref commitments_bytes, commitment2);

    let mut challenges_bytes: Array<u8> = ArrayTrait::new();
    append_scalar_be32(ref challenges_bytes, challenge1);
    append_scalar_be32(ref challenges_bytes, challenge2);

    let mut responses_bytes: Array<u8> = ArrayTrait::new();
    append_scalar_be32(ref responses_bytes, response1);
    append_scalar_be32(ref responses_bytes, response2);

    assert_ok(
        verify_ring_bytes(
            keys_bytes.span(),
            commitments_bytes.span(),
            challenges_bytes.span(),
            responses_bytes.span(),
            ctx(9).span(),
        ),
        'RING_BYTES_FAIL',
    );
}

#[test]
fn batch_schnorr_bytes_single_instance() {
    let g = generator();
    let secret: felt252 = 7;
    let nonce: felt252 = 9;
    let public_key = mul_point(secret, g);
    let commitment = mul_point(nonce, g);
    let statement = SchnorrStatement { public_key };
    let preproof = SchnorrProof { commitment, response: 0 };
    let challenge = derive_challenge(
        SigmaStatement::Schnorr(statement),
        SigmaProof::Schnorr(preproof),
        ctx(150).span(),
    ).unwrap();
    let response = add_mod_order(nonce, mul_mod_order(challenge, secret));

    let mut statements_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref statements_bytes, public_key);

    let mut proofs_bytes: Array<u8> = ArrayTrait::new();
    append_point_be64(ref proofs_bytes, commitment);
    append_scalar_be32(ref proofs_bytes, response);

    assert_ok(
        batch_verify_schnorr_bytes(statements_bytes.span(), proofs_bytes.span(), ctx(150).span()),
        'BATCH_S_BYTES_FAIL',
    );
}

#[test]
fn batch_verifiers_cover_all_protocols() {
    let g = generator();
    let h = pedersen_h();

    let schnorr_secret: felt252 = 7;
    let schnorr_nonce: felt252 = 9;
    let schnorr_public_key = mul_point(schnorr_secret, g);
    let schnorr_commitment = mul_point(schnorr_nonce, g);
    let schnorr_stmt = SchnorrStatement { public_key: schnorr_public_key };
    let schnorr_pre = SchnorrProof { commitment: schnorr_commitment, response: 0 };
    let schnorr_challenge = derive_challenge(
        SigmaStatement::Schnorr(schnorr_stmt),
        SigmaProof::Schnorr(schnorr_pre),
        ctx(50).span(),
    ).unwrap();
    let schnorr_response = add_mod_order(schnorr_nonce, mul_mod_order(schnorr_challenge, schnorr_secret));
    let schnorr_proof = SchnorrProof { commitment: schnorr_commitment, response: schnorr_response };
    let mut schnorr_statements = ArrayTrait::new();
    schnorr_statements.append(schnorr_stmt);
    let mut schnorr_proofs = ArrayTrait::new();
    schnorr_proofs.append(schnorr_proof);
    assert_ok(
        batch_verify_schnorr(schnorr_statements.span(), schnorr_proofs.span(), ctx(50).span()),
        'BATCH_S_OK',
    );
    let mut schnorr_bad = ArrayTrait::new();
    schnorr_bad.append(SchnorrProof {
        commitment: schnorr_commitment,
        response: add_mod_order(schnorr_response, 1),
    });
    assert_err(
        batch_verify_schnorr(schnorr_statements.span(), schnorr_bad.span(), ctx(50).span()),
        'BATCH_S_BAD',
    );

    let dlog_base = h;
    let dlog_secret: felt252 = 5;
    let dlog_nonce: felt252 = 8;
    let dlog_public_key = mul_point(dlog_secret, dlog_base);
    let dlog_commitment = mul_point(dlog_nonce, dlog_base);
    let dlog_stmt = DLogStatement { base: dlog_base, public_key: dlog_public_key };
    let dlog_pre = DLogProof { commitment: dlog_commitment, response: 0 };
    let dlog_challenge = derive_challenge(
        SigmaStatement::DLog(dlog_stmt),
        SigmaProof::DLog(dlog_pre),
        ctx(51).span(),
    ).unwrap();
    let dlog_response = add_mod_order(dlog_nonce, mul_mod_order(dlog_challenge, dlog_secret));
    let dlog_proof = DLogProof { commitment: dlog_commitment, response: dlog_response };
    let mut dlog_statements = ArrayTrait::new();
    dlog_statements.append(dlog_stmt);
    let mut dlog_proofs = ArrayTrait::new();
    dlog_proofs.append(dlog_proof);
    assert_ok(
        batch_verify_dlog(dlog_statements.span(), dlog_proofs.span(), ctx(51).span()),
        'BATCH_D_OK',
    );
    let mut dlog_bad = ArrayTrait::new();
    dlog_bad.append(DLogProof {
        commitment: dlog_commitment,
        response: add_mod_order(dlog_response, 1),
    });
    assert_err(
        batch_verify_dlog(dlog_statements.span(), dlog_bad.span(), ctx(51).span()),
        'BATCH_D_BAD',
    );

    let cp_h = mul_point(13, g);
    let cp_secret: felt252 = 6;
    let cp_nonce: felt252 = 10;
    let cp_y1 = mul_point(cp_secret, g);
    let cp_y2 = mul_point(cp_secret, cp_h);
    let cp_r1 = mul_point(cp_nonce, g);
    let cp_r2 = mul_point(cp_nonce, cp_h);
    let cp_stmt = ChaumPedStatement { y1: cp_y1, y2: cp_y2, h: cp_h };
    let cp_pre = ChaumPedProof { r1: cp_r1, r2: cp_r2, response: 0 };
    let cp_challenge = derive_challenge(
        SigmaStatement::ChaumPed(cp_stmt),
        SigmaProof::ChaumPed(cp_pre),
        ctx(52).span(),
    ).unwrap();
    let cp_response = add_mod_order(cp_nonce, mul_mod_order(cp_challenge, cp_secret));
    let cp_proof = ChaumPedProof { r1: cp_r1, r2: cp_r2, response: cp_response };
    let mut cp_statements = ArrayTrait::new();
    cp_statements.append(cp_stmt);
    let mut cp_proofs = ArrayTrait::new();
    cp_proofs.append(cp_proof);
    assert_ok(
        batch_verify_chaum_ped(cp_statements.span(), cp_proofs.span(), ctx(52).span()),
        'BATCH_CP_OK',
    );
    let mut cp_bad = ArrayTrait::new();
    cp_bad.append(ChaumPedProof {
        r1: cp_r1,
        r2: cp_r2,
        response: add_mod_order(cp_response, 1),
    });
    assert_err(
        batch_verify_chaum_ped(cp_statements.span(), cp_bad.span(), ctx(52).span()),
        'BATCH_CP_BAD',
    );

    let mut ok_bases = ArrayTrait::new();
    ok_bases.append(g);
    ok_bases.append(h);
    let ok_x1: felt252 = 4;
    let ok_x2: felt252 = 7;
    let ok_k1: felt252 = 8;
    let ok_k2: felt252 = 12;
    let ok_y = add_points(mul_point(ok_x1, g), mul_point(ok_x2, h));
    let ok_commitment = add_points(mul_point(ok_k1, g), mul_point(ok_k2, h));
    let ok_stmt = OkamotoStatement { bases: ok_bases.span(), y: ok_y };
    let mut ok_zero_responses = ArrayTrait::new();
    ok_zero_responses.append(0);
    ok_zero_responses.append(0);
    let ok_pre = OkamotoProof { commitment: ok_commitment, responses: ok_zero_responses.span() };
    let ok_challenge = derive_challenge(
        SigmaStatement::Okamoto(ok_stmt),
        SigmaProof::Okamoto(ok_pre),
        ctx(53).span(),
    ).unwrap();
    let ok_r1 = add_mod_order(ok_k1, mul_mod_order(ok_challenge, ok_x1));
    let ok_r2 = add_mod_order(ok_k2, mul_mod_order(ok_challenge, ok_x2));
    let mut ok_responses = ArrayTrait::new();
    ok_responses.append(ok_r1);
    ok_responses.append(ok_r2);
    let ok_proof = OkamotoProof { commitment: ok_commitment, responses: ok_responses.span() };
    let mut ok_statements = ArrayTrait::new();
    ok_statements.append(ok_stmt);
    let mut ok_proofs = ArrayTrait::new();
    ok_proofs.append(ok_proof);
    assert_ok(
        batch_verify_okamoto(ok_statements.span(), ok_proofs.span(), ctx(53).span()),
        'BATCH_OK_OK',
    );
    let mut ok_bad_responses = ArrayTrait::new();
    ok_bad_responses.append(add_mod_order(ok_r1, 1));
    ok_bad_responses.append(ok_r2);
    let mut ok_bad = ArrayTrait::new();
    ok_bad.append(OkamotoProof { commitment: ok_commitment, responses: ok_bad_responses.span() });
    assert_err(
        batch_verify_okamoto(ok_statements.span(), ok_bad.span(), ctx(53).span()),
        'BATCH_OK_BAD',
    );

    let ped_value: felt252 = 11;
    let ped_blinding: felt252 = 14;
    let ped_nonce_value: felt252 = 6;
    let ped_nonce_blinding: felt252 = 9;
    let ped_commitment = add_points(mul_point(ped_value, g), mul_point(ped_blinding, h));
    let ped_nonce_commitment = add_points(
        mul_point(ped_nonce_value, g), mul_point(ped_nonce_blinding, h)
    );
    let ped_stmt = PedersenStatement {
        value_base: g,
        blinding_base: h,
        commitment: ped_commitment,
    };
    let ped_pre = PedersenProof {
        nonce_commitment: ped_nonce_commitment,
        response_value: 0,
        response_blinding: 0,
    };
    let ped_challenge = derive_challenge(
        SigmaStatement::Pedersen(ped_stmt),
        SigmaProof::Pedersen(ped_pre),
        ctx(54).span(),
    ).unwrap();
    let ped_response_value = add_mod_order(ped_nonce_value, mul_mod_order(ped_challenge, ped_value));
    let ped_response_blinding = add_mod_order(
        ped_nonce_blinding, mul_mod_order(ped_challenge, ped_blinding)
    );
    let ped_proof = PedersenProof {
        nonce_commitment: ped_nonce_commitment,
        response_value: ped_response_value,
        response_blinding: ped_response_blinding,
    };
    let mut ped_statements = ArrayTrait::new();
    ped_statements.append(ped_stmt);
    let mut ped_proofs = ArrayTrait::new();
    ped_proofs.append(ped_proof);
    assert_ok(
        batch_verify_pedersen(ped_statements.span(), ped_proofs.span(), ctx(54).span()),
        'BATCH_P_OK',
    );
    let mut ped_bad = ArrayTrait::new();
    ped_bad.append(PedersenProof {
        nonce_commitment: ped_nonce_commitment,
        response_value: add_mod_order(ped_response_value, 1),
        response_blinding: ped_response_blinding,
    });
    assert_err(
        batch_verify_pedersen(ped_statements.span(), ped_bad.span(), ctx(54).span()),
        'BATCH_P_BAD',
    );

    let eq_value_base2 = mul_point(19, g);
    let eq_blinding_base2 = mul_point(23, g);
    let eq_value: felt252 = 5;
    let eq_blinding1: felt252 = 7;
    let eq_blinding2: felt252 = 9;
    let eq_nonce_value: felt252 = 4;
    let eq_nonce_blinding1: felt252 = 6;
    let eq_nonce_blinding2: felt252 = 8;
    let eq_commitment1 = add_points(mul_point(eq_value, g), mul_point(eq_blinding1, h));
    let eq_commitment2 = add_points(
        mul_point(eq_value, eq_value_base2), mul_point(eq_blinding2, eq_blinding_base2)
    );
    let eq_nonce_commitment1 = add_points(
        mul_point(eq_nonce_value, g), mul_point(eq_nonce_blinding1, h)
    );
    let eq_nonce_commitment2 = add_points(
        mul_point(eq_nonce_value, eq_value_base2),
        mul_point(eq_nonce_blinding2, eq_blinding_base2),
    );
    let eq_stmt = PedersenEqStatement {
        commitment1: eq_commitment1,
        commitment2: eq_commitment2,
        value_base1: g,
        blinding_base1: h,
        value_base2: eq_value_base2,
        blinding_base2: eq_blinding_base2,
    };
    let eq_pre = PedersenEqProof {
        nonce_commitment1: eq_nonce_commitment1,
        nonce_commitment2: eq_nonce_commitment2,
        response_value: 0,
        response_blinding1: 0,
        response_blinding2: 0,
    };
    let eq_challenge = derive_challenge(
        SigmaStatement::PedersenEq(eq_stmt),
        SigmaProof::PedersenEq(eq_pre),
        ctx(55).span(),
    ).unwrap();
    let eq_response_value = add_mod_order(eq_nonce_value, mul_mod_order(eq_challenge, eq_value));
    let eq_response_blinding1 = add_mod_order(
        eq_nonce_blinding1, mul_mod_order(eq_challenge, eq_blinding1)
    );
    let eq_response_blinding2 = add_mod_order(
        eq_nonce_blinding2, mul_mod_order(eq_challenge, eq_blinding2)
    );
    let eq_proof = PedersenEqProof {
        nonce_commitment1: eq_nonce_commitment1,
        nonce_commitment2: eq_nonce_commitment2,
        response_value: eq_response_value,
        response_blinding1: eq_response_blinding1,
        response_blinding2: eq_response_blinding2,
    };
    let mut eq_statements = ArrayTrait::new();
    eq_statements.append(eq_stmt);
    let mut eq_proofs = ArrayTrait::new();
    eq_proofs.append(eq_proof);
    assert_ok(
        batch_verify_pedersen_eq(eq_statements.span(), eq_proofs.span(), ctx(55).span()),
        'BATCH_EQ_OK',
    );
    let mut eq_bad = ArrayTrait::new();
    eq_bad.append(PedersenEqProof {
        nonce_commitment1: eq_nonce_commitment1,
        nonce_commitment2: eq_nonce_commitment2,
        response_value: add_mod_order(eq_response_value, 1),
        response_blinding1: eq_response_blinding1,
        response_blinding2: eq_response_blinding2,
    });
    assert_err(
        batch_verify_pedersen_eq(eq_statements.span(), eq_bad.span(), ctx(55).span()),
        'BATCH_EQ_BAD',
    );

    let rerand_value: felt252 = 3;
    let rerand_blinding: felt252 = 4;
    let rerand_secret: felt252 = 7;
    let rerand_nonce: felt252 = 11;
    let rerand_commitment_from = add_points(
        mul_point(rerand_value, g), mul_point(rerand_blinding, h)
    );
    let rerand_commitment_to = add_points(rerand_commitment_from, mul_point(rerand_secret, h));
    let rerand_nonce_commitment = mul_point(rerand_nonce, h);
    let rerand_stmt = PedersenRerandStatement {
        rerand_base: h,
        commitment_from: rerand_commitment_from,
        commitment_to: rerand_commitment_to,
    };
    let rerand_pre = PedersenRerandProof {
        nonce_commitment: rerand_nonce_commitment,
        response: 0,
    };
    let rerand_challenge = derive_challenge(
        SigmaStatement::PedersenRerand(rerand_stmt),
        SigmaProof::PedersenRerand(rerand_pre),
        ctx(56).span(),
    ).unwrap();
    let rerand_response = add_mod_order(
        rerand_nonce, mul_mod_order(rerand_challenge, rerand_secret)
    );
    let rerand_proof = PedersenRerandProof {
        nonce_commitment: rerand_nonce_commitment,
        response: rerand_response,
    };
    let mut rerand_statements = ArrayTrait::new();
    rerand_statements.append(rerand_stmt);
    let mut rerand_proofs = ArrayTrait::new();
    rerand_proofs.append(rerand_proof);
    assert_ok(
        batch_verify_pedersen_rerand(
            rerand_statements.span(), rerand_proofs.span(), ctx(56).span()
        ),
        'BATCH_R_OK',
    );
    let mut rerand_bad = ArrayTrait::new();
    rerand_bad.append(PedersenRerandProof {
        nonce_commitment: rerand_nonce_commitment,
        response: add_mod_order(rerand_response, 1),
    });
    assert_err(
        batch_verify_pedersen_rerand(
            rerand_statements.span(), rerand_bad.span(), ctx(56).span()
        ),
        'BATCH_R_BAD',
    );
}

#[test]
fn derive_challenge_rejects_invalid_rerand_statement() {
    let h = pedersen_h();
    let commitment = mul_point(17, generator());
    let nonce_commitment = mul_point(9, h);

    let stmt = SigmaStatement::PedersenRerand(PedersenRerandStatement {
        rerand_base: h,
        commitment_from: commitment,
        commitment_to: commitment,
    });
    let proof = SigmaProof::PedersenRerand(PedersenRerandProof {
        nonce_commitment,
        response: 5,
    });
    match derive_challenge(stmt, proof, ctx(57).span()) {
        Result::Ok(_) => {
            core::panic_with_felt252('RERAND_DERIVE_INVALID');
        },
        Result::Err(err) => {
            if err != VerifyError::InvalidStatement {
                core::panic_with_felt252('RERAND_DERIVE_INVALID');
            }
        },
    }
}
