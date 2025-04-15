use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use paste::paste;

use p256::NistP256 as P256;
use p384::NistP384 as P384;
use p521::NistP521 as P521;
use rand::{rngs::StdRng, SeedableRng};
use voprf::{PoprfClient, PoprfServer, Ristretto255};

macro_rules! make_poprf_benches {
    ($cipher_suite:ident) => {

        paste! {
            fn [<bench_poprf_client_blind_ $cipher_suite:lower>](c: &mut Criterion) {
                let rng = StdRng::seed_from_u64(0_u64);
                c.bench_function(&format!("{}_{}", "poprf_client_blind", stringify!($cipher_suite).to_lowercase()), move |b| {
                    b.iter_batched_ref(
                        || rng.clone(),
                        |mut rng| {
                            PoprfClient::<$cipher_suite>::blind(b"input", &mut rng)
                                .expect("Unable to construct client")
                        },
                        BatchSize::SmallInput,
                    )
                });
            }
        }

        paste! {
            fn [<bench_poprf_server_evaluate_ $cipher_suite:lower>](c: &mut Criterion) {
                let mut rng = StdRng::seed_from_u64(0_u64);
                let server = PoprfServer::<$cipher_suite>::new(&mut rng).unwrap();
                let client_blind_result =
                    PoprfClient::<$cipher_suite>::blind(b"input", &mut rng).expect("Unable to construct client");
                c.bench_function(&format!("{}_{}", "poprf_server_eval", stringify!($cipher_suite).to_lowercase()), move |b| {
                    b.iter_batched_ref(
                        || rng.clone(),
                        |mut rng| {
                            server
                                .blind_evaluate(&mut rng, &client_blind_result.message, Some(b"tag"))
                                .expect("Unable to perform server evaluation")
                        },
                        BatchSize::SmallInput,
                    )
                });
            }
        }

        paste! {
            fn [<bench_poprf_client_finalize_ $cipher_suite:lower>](c: &mut Criterion) {
                let mut rng = StdRng::seed_from_u64(0_u64);
                let server = PoprfServer::<$cipher_suite>::new(&mut rng).unwrap();
                let client_blind_result =
                    PoprfClient::<$cipher_suite>::blind(b"input", &mut rng).expect("Unable to construct client");
                let server_evaluate_result = server
                    .blind_evaluate(&mut rng, &client_blind_result.message, Some(b"tag"))
                    .expect("Unable to perform server evaluation");
                c.bench_function(&format!("{}_{}", "poprf_client_final", stringify!($cipher_suite).to_lowercase()), move |b| {
                    b.iter(|| {
                        client_blind_result
                            .state
                            .finalize(
                                b"input",
                                &server_evaluate_result.message,
                                &server_evaluate_result.proof,
                                server.get_public_key(),
                                Some(b"tag"),
                            )
                            .expect("Unable to perform client finalization")
                    })
                });
            }
        }

    };
}

make_poprf_benches!(Ristretto255);
make_poprf_benches!(P256);
make_poprf_benches!(P384);
make_poprf_benches!(P521);

criterion_group!(
    poprf,
    bench_poprf_client_blind_ristretto255,
    bench_poprf_server_evaluate_ristretto255,
    bench_poprf_client_finalize_ristretto255,
    bench_poprf_client_blind_p256,
    bench_poprf_server_evaluate_p256,
    bench_poprf_client_finalize_p256,
    bench_poprf_client_blind_p384,
    bench_poprf_server_evaluate_p384,
    bench_poprf_client_finalize_p384,
    bench_poprf_client_blind_p521,
    bench_poprf_server_evaluate_p521,
    bench_poprf_client_finalize_p521
);
criterion_main!(poprf);
