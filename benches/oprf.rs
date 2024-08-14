use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use paste::paste;

use rand::{rngs::StdRng, SeedableRng};
use voprf::{Ristretto255, OprfClient, OprfServer};
use p256::NistP256 as P256;
use p384::NistP384 as P384;
use p521::NistP521 as P521;

macro_rules! make_oprf_benches {
    ($cipher_suite:ident) => {

        paste! {
            fn [<bench_oprf_client_blind_ $cipher_suite:lower>](c: &mut Criterion) {
                let rng = StdRng::seed_from_u64(0_u64);
                c.bench_function(&format!("{}_{}", "oprf_client_blind", stringify!($cipher_suite).to_lowercase()), move |b| {
                    b.iter_batched_ref(
                        || rng.clone(),
                        |mut rng| {
                            OprfClient::<$cipher_suite>::blind(b"input", &mut rng)
                                .expect("Unable to construct client")
                        },
                        BatchSize::SmallInput,
                    )
                });
            }
        }

        paste! {
            fn [<bench_oprf_server_evaluate_ $cipher_suite:lower>](c: &mut Criterion) {
                let mut rng = StdRng::seed_from_u64(0_u64);
                let server = OprfServer::<$cipher_suite>::new(&mut rng).unwrap();
                let client_blind_result =
                    OprfClient::<$cipher_suite>::blind(b"input", &mut rng).expect("Unable to construct client");
                c.bench_function(&format!("{}_{}", "oprf_server_eval", stringify!($cipher_suite).to_lowercase()), move |b| {
                    b.iter(
                        || {
                            server
                                .blind_evaluate(&client_blind_result.message);
                        }
                    )
                });
            }
        }

        paste! {
            fn [<bench_oprf_client_finalize_ $cipher_suite:lower>](c: &mut Criterion) {
                let mut rng = StdRng::seed_from_u64(0_u64);
                let server = OprfServer::<$cipher_suite>::new(&mut rng).unwrap();
                let client_blind_result =
                    OprfClient::<$cipher_suite>::blind(b"input", &mut rng).expect("Unable to construct client");
                let server_evaluate_result = server
                    .blind_evaluate(&client_blind_result.message);
                c.bench_function(&format!("{}_{}", "oprf_client_final", stringify!($cipher_suite).to_lowercase()), move |b| {
                    b.iter(|| {
                        client_blind_result
                            .state
                            .finalize(
                                b"input",
                                &server_evaluate_result,
                            )
                            .expect("Unable to perform client finalization")
                    })
                });
            }
        }

    };
}

make_oprf_benches!(Ristretto255);
make_oprf_benches!(P256);
make_oprf_benches!(P384);
make_oprf_benches!(P521);

criterion_group!(
    oprf,
    bench_oprf_client_blind_ristretto255,
    bench_oprf_server_evaluate_ristretto255,
    bench_oprf_client_finalize_ristretto255,
    bench_oprf_client_blind_p256,
    bench_oprf_server_evaluate_p256,
    bench_oprf_client_finalize_p256,
    bench_oprf_client_blind_p384,
    bench_oprf_server_evaluate_p384,
    bench_oprf_client_finalize_p384,
    bench_oprf_client_blind_p521,
    bench_oprf_server_evaluate_p521,
    bench_oprf_client_finalize_p521
);
criterion_main!(oprf);
