use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

use rand::{rngs::StdRng, SeedableRng};
use voprf::{PoprfClient, PoprfServer, Ristretto255};

fn bench_client_blind(c: &mut Criterion) {
    let rng = StdRng::seed_from_u64(0_u64);
    c.bench_function("client_blind", move |b| {
        b.iter_batched_ref(
            || rng.clone(),
            |mut rng| {
                PoprfClient::<Ristretto255>::blind(b"input", &mut rng)
                    .expect("Unable to construct client")
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_server_evaluate(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0_u64);
    let server = PoprfServer::<Ristretto255>::new(&mut rng).unwrap();
    let client_blind_result =
        PoprfClient::<Ristretto255>::blind(b"input", &mut rng).expect("Unable to construct client");
    c.bench_function("server_eval", move |b| {
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

fn bench_client_finalize(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0_u64);
    let server = PoprfServer::<Ristretto255>::new(&mut rng).unwrap();
    let client_blind_result =
        PoprfClient::<Ristretto255>::blind(b"input", &mut rng).expect("Unable to construct client");
    let server_evaluate_result = server
        .blind_evaluate(&mut rng, &client_blind_result.message, Some(b"tag"))
        .expect("Unable to perform server evaluation");
    c.bench_function("client_final", move |b| {
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

criterion_group!(
    poprf,
    bench_client_blind,
    bench_server_evaluate,
    bench_client_finalize
);
criterion_main!(poprf);
