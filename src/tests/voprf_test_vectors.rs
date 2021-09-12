// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use crate::ciphersuite::CipherSuite;
use crate::errors::*;
use crate::group::Group;
use crate::tests::{mock_rng::CycleRng, parser::*};
use crate::voprf::{NonVerifiableClient, NonVerifiableServer};
use alloc::string::ToString;
use alloc::vec::Vec;
use curve25519_dalek::ristretto::RistrettoPoint;
use generic_array::GenericArray;
use json::JsonValue;
use sha2::Sha512;

#[derive(Debug)]
struct VOPRFTestVectorParameters {
    seed: Vec<u8>,
    sksm: Vec<u8>,
    input: Vec<Vec<u8>>,
    info: Vec<u8>,
    blind: Vec<Vec<u8>>,
    blinded_element: Vec<Vec<u8>>,
    evaluation_element: Vec<Vec<u8>>,
    output: Vec<Vec<u8>>,
}

// Taken from https://github.com/cfrg/draft-irtf-cfrg-voprf/blob/master/draft-irtf-cfrg-voprf.md
// in base mode
#[cfg(feature = "p256")]
static OPRF_P256_SHA256: &[&str] = &[
    r#"
    {
        "sksm": "a1b2355828f2c76de6749af9d093bd9fe0f2cada3ec653cd9a6d3126a7a7827b",
        "input": "00",
        "blind": "5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98af0d0",
        "blinded_element": "03e3c379698da853d9844098fa0ac676970d5ec24167b598714cd2ee188604ddd2",
        "evaluation_element": "03ea54e8d095332d1a601a3f8a5013188aea036bf9b563236f7fd3b046908b42fd",
        "output": "464e3e51e4086a824d9a2f939524d7069ae4072a788bc9d5daa0762b25826437"
    }
    "#,
    r#"
    {
        "sksm": "a1b2355828f2c76de6749af9d093bd9fe0f2cada3ec653cd9a6d3126a7a7827b",
        "input": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "blind": "825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5fcbe",
        "blinded_element": "030b40be181ffbb3c3ae4a4911287c43261f5e4034781def69c51608f372a02102",
        "evaluation_element": "03115ad70ea55dbb4006da0ee3589a3582f31ef9cd143996d1e31a25ad3abdcf6f",
        "output": "b597d58c843d0f9d2712121b0a3e2912ebee1c829eed3089eade9af4359ab275"
    }
    "#,
];

static OPRF_TEST_VECTORS: &str = r#"
## OPRF(ristretto255, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = caeff69352df4905a9121a4997704ca8cee1524a110819eb87deba1a39ec1
701
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = c604c785ada70d77a5256ae21767de8c3304115237d262134f5e46e512cf
8e03
BlindedElement = fc20e03aff3a9de9b37e8d35886ade11ec7d85c2a1fb5bb0b16
86c64e07ac467
EvaluationElement = 922e4c04b9f3b3e795d322a306c0ab9d96b667df9b949c05
2c8c75435a9dbf2f
Output = 9e857d0e8523b8eb9e995d455ae6ae19f75d85ac8b5df62c50616fb5aa0
ced3da5646698089c36dead28f9ad8e489fc0ee1c8e168725c38ed50f3783a5c520c
e
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5ed895206bfc53316d307b23e46ecc6623afb3086da74189a416012be037
e50b
BlindedElement = 483d4f39de5ff77fa0f9a0ad2334dd5bf87f2cda868539d21de
67ce49e7d1536
EvaluationElement = 6eef6ee53c6fb17c77ae47e78bdca2e1094f98785e7b9a14
f09be20797dad656
Output = b090b2ff80028771c14fecf2f37c1b14e46deec59c83d3b943c51d315bd
3bf7d32c399ed0c4ce6003339ab9ed4ad168bfb595e43530c9d73ff02ab0f1263d93
b
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = ac37d5850510299406ea8eb8fa226a7bfc2467a4b070d6c7bf667948b9600
b00
pkSm = 0c0254e22063cae3e1bae02fb6fa20882664a117c0278eda6bda3372c0dd9
860
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = ed8366feb6b1d05d1f46acb727061e43aadfafe9c10e5a64e7518d63e326
3503
BlindedElement = 3a0a53f2c57e5ee0d89e394087f8e5f95b24159db01c31933a0
7f0e6414c954d
EvaluationElement = f8a50ed35a477b0cde91d926e1bc5ae59b97d5bd0dda51a7
28b0f036ec557d79
EvaluationProofC = 7a5375eb1dbad259431f5c294e816a1c1483c279748da1a75
d91f8a81438ea08
EvaluationProofS = 355d4087d4d848b46878dcc8fb5849ac7a09133382c2c6129
564a7f7b4b7bf01
Output = 4b2ff4c984985829c3cd9d90c255cdc0d6b61c4c0aafa9215769d51cf7d
eb01472ba945928a8305e010f12b7dcc75a9dc2460439e6297d57dc2ce7ca0abaae1
a
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = e6d0f1d89ad552e383d6c6f4e8598cc3037d6e274d22da3089e7afbd4171
ea02
BlindedElement = a86dd4544d0f3ea973926054230767dff16016215f2d73f26d3
f86a81f38cf1a
EvaluationElement = 9e47810f1de1b57ebe163a95c170ec165a2063f872155c37
6d94e8de2157af70
EvaluationProofC = 61075125d851d5164b0aa1a4d5ddeebaf097266450ac60195
79af5f7abd19008
EvaluationProofS = 8eb0f6f1e7f9d8bfddbc21ae3c25a065e6c4e797d15f345ed
4fb9ee468d24c0a
Output = fe1fb7fa49c37dc7cd31d64859b4a2e6ae0cef294f2764e6f12f7d809f2
18047d1fde147cf69807b8971fb2c316eb572be2b5bf491813bfec0a20668d6d07b0
b
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 80513e77795feeec6d2c450589b0e1b178febd5c193a9fcba0d27f0a06e0
d50f,533c2e6d91c934f919ac218973be55ba0d7b234160a0d4cf3bddafbda99e2e0
c
BlindedElement = c24645d6378a4a86ec4682a8d86f368b1e7db870fd709a45102
492bcdc17e904,0e5ec78f839a8b6e86999bc180602690a4daae57bf5d7f827f3d40
2f56cc6c51
EvaluationElement = 3afe48eab00493eb1b073e95f57a456cde9aefe463dd1e6d
0144bf6e99ce411c,daaf9421318fd2c7fcdf369cb348748cf4dd177cce30ee4d13c
eb1644b85b653
EvaluationProofC = 601381ecbe127ada04c057b8b1fc21d912f71e49252780dd0
d0ac768b233ce03
EvaluationProofS = 5f9b489a994c1d14b92d603ebcffee4f5cfadc953f69bb626
48c6e662613ae00
Output = 4b2ff4c984985829c3cd9d90c255cdc0d6b61c4c0aafa9215769d51cf7d
eb01472ba945928a8305e010f12b7dcc75a9dc2460439e6297d57dc2ce7ca0abaae1
a,fe1fb7fa49c37dc7cd31d64859b4a2e6ae0cef294f2764e6f12f7d809f218047d1
fde147cf69807b8971fb2c316eb572be2b5bf491813bfec0a20668d6d07b0b
~~~

## OPRF(decaf448, SHAKE-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 78f2622804104209f7e015370ff98f4a3cbf311e6784e9f4944f8a252dc08
e916d9ab1a60dc905f0e56631903ecd4ae6e15291776d61460b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = d1080372f0fcf8c5eace50914e7127f576725f215cc7c111673c635ce668
bbbb9b50601ad89b358ab8c23ed0b6c9d040365ec9d060868714
BlindedElement = 984e0a443ee194090737df4afb402253f216b77650c91d252b6
638e1179723d51a4154b88eae396f1320f5df3c4b17f779516c456e364bd1
EvaluationElement = de477252a5ff3c7d51ce159cb8ccf1865d8c7d3402824163
8d80971f13a59d87b2b1036341b98089555ab088278391794c49bbb052fdbcff
Output = df8f910c3b84d1f3ca6afd1992768608a20f2ad7b770e9d89d303c88ba1
5bb7d991f2f7ffd5b5b51fa3bcf8fa06779609497f6c0ae4e9cb2dcd48c68b4ac6b9
4
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = aed1ffa44fd8f0ed16373606a3cf7df589cca86d8ea1abbf5768771dbef3
d401c74ae55ba1e28b9565e1e4018eb261a14134a4ce60c1c718
BlindedElement = 4aa751f84b2634b73efa364b03e60b92b84f457576e6b369eea
b76140e3859d10d2e98174f13f5a2c70670529ccf093d5f1aaf355b4f830b
EvaluationElement = 085ea1cb452a2fb15b3a0d0e1c86899c7ea49fe2e4856ef4
f95bc2542eec610fc09b0fe7d7ed7389d86af6a646695b7ad46527dc2a936aa4
Output = b57516a737879ece1110ad5d051ac0a6c54e1dcd989c907721ecebab5b4
5877cc693c3c05d0bd416c5a9ceba36de41a0a31679c146fe4c110c64b056eba1720
b
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 9eb722f7fee9f61f24ad31bc42309f73648cf4393929e8f5f333fe10c6975
c827a1eba4e03ae2fa8735db2f63f6c98c7af6010e64c81f535
pkSm = b6e2751176d57836fe1dfbdbbdc78a1b5c5a52f831226c9d8dfdf5daf8f46
6e310e80978e9b81c387f5bc85cc7ef5567f4dd3ba7674579a2
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 4c936db1779a621b6c71475ac3111fd5703a59b713929f36dfd1e892a7fe
814479c93d8b4b6e11d1f6fe5351e51457b665fa7b76074e531f
BlindedElement = d0b8e2eecad2816d45c1f8a072fe6db77d18f4b26f0889c98e2
ef856ac5df82090c1fbeac9c8e732f192b66c3b4c3f1e446ab8910c86be2f
EvaluationElement = d29849d8ad1e651328e8119003debd9ecd54cc786a5eb8ae
ea56487ffc09120e98792f9475605488d16623b8e3cfa5af1ec27e76bc841b75
EvaluationProofC = 8b3b8f0c9eb22527e419f5a03d4d3f34cf725837424a38c5b
4f88c7759f7a54bade57b7930bfeff051be9bfeaabc8976ed407398e0ce462a
EvaluationProofS = 062e068a8d57bc1c411bc42fe714626cfb92ad854a56636c2
b83f2b5215c2ff531b22e4d37031523db203556959e275b46b84303ed23fc37
Output = 1ff5c5c2c081c76006b52c45f79728882dc48962036ea7d4d5097b04e93
9ae81118a7fe5f0a66a6131bef18b9cd998150f10c62619ec4c2d223ea57dc67f153
d
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 15b3355179392f40c3d5a15f0d5ffc354e340454ec779f575e4573a3886a
b5e57e4da2985cea9e32f6d95539ce2c7189e1bd7462e8c5483a
BlindedElement = 0e7ddd85c8bc5382e908241c6151afe23a41e0396759b5e38a9
affd996cd822bca242a499793555fc15f07bffdaaa93b42568b307fbdca0f
EvaluationElement = 4c81e29e8a9502fa02e00cb09cf40d9b98988ac9b4bce7cc
a0656caeb0926b59c7000d7fe6c5dd814f831864547d2360d223a50077bd04fe
EvaluationProofC = 74fc8fbf2e669dc5d25898ea8ce45d1d3eb97edb4b7c3cee3
9865a3c66da6b7bad4ad3e77794d6f5e82fa8a645b9b973a8612bfcd1194302
EvaluationProofS = f700ee3433e876d83f96bb70f19ff292605ad4c9466fd71db
c2ed22ade0130574e5ee343ef45d42e834a11a19fd6f5b1b5ef910bcccf731b
Output = 2753e222528f1ee5fcc6ad4bf1ca953e5d3b47c1dfae85710f46a0a030c
07f59055e9b05dacb729a7ce41cd2ed782f8a76a1b3f74b40196aed0b6938b89c60f
9
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 614bb578f29cc677ea9e7aea3e4839413997e020f9377b63c13584156a09
a46dd2a425c41eac0e313a47e99d05df72c6e1d58e6592577a0d,4c115060bca87db
7d73e00cbb8559f84cb7a221b235b0950a0ab553f03f10e1386abe954011b7da62bb
6599418ef90b5d4ea98cc28aff517
BlindedElement = 5e481a4d7eaa5bab831f53f9a6311851dafd4318c6462eed4f6
15004afdb082da2f99670b0963985faac21c30eea19aacfc441412edb4c0b,8e043b
9b7afeafa07e39d9b8b88957ff07d69124b1a2b841e18c9ffb52ebf0c25144eb2501
a1d7983a44604f33a36e925eebc9bec65d9c54
EvaluationElement = 8a0d34fdb0b55121421546ff952c7bd3cbe469926ff9ad4f
aeba243823955529eeae4f1a7a64cd055ec01baa041a99dfbe1a67ca4d59f93d,5e8
6e0b41cc88186ee0003baa46535e71acd98453b298976b92be2cca2646e88620f55d
f6bf4754456dfd8d84f6889c17b5ff93052325a1a
EvaluationProofC = 1ff624a102b99771c76a9414e9b3f33127897d971bc84a922
e464805e4a9f27b889922030adebbbd58e0ab618ade9c84bfe8aa226176f11f
EvaluationProofS = 432958ea1e6f69263aef51db9efb23ee504d233c17e9077c0
373401da167637a1df4eafd9c2537c9f89c103f9e635931fe2042419dd9bd37
Output = 1ff5c5c2c081c76006b52c45f79728882dc48962036ea7d4d5097b04e93
9ae81118a7fe5f0a66a6131bef18b9cd998150f10c62619ec4c2d223ea57dc67f153
d,2753e222528f1ee5fcc6ad4bf1ca953e5d3b47c1dfae85710f46a0a030c07f5905
5e9b05dacb729a7ce41cd2ed782f8a76a1b3f74b40196aed0b6938b89c60f9
~~~

## OPRF(P-256, SHA-256)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = a1b2355828f2c76de6749af9d093bd9fe0f2cada3ec653cd9a6d3126a7a78
27b
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 5d9e7f6efd3093c32ecceabd57fb03cf760c926d2a7bfa265babf29ec98a
f0d0
BlindedElement = 03e3c379698da853d9844098fa0ac676970d5ec24167b598714
cd2ee188604ddd2
EvaluationElement = 030d8d882120e8fa67ef978a9abac506acd5ec731b8e8d6f
15035e29241dd2ced2
Output = ab653a4f3b357177b125e1c6d0bd2c0bc409b7ed5f48c99537fbd7fd11e
f8133
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 825155ab61f17605af2ae2e935c78d857c9407bcd45128d57d338f1671b5
fcbe
BlindedElement = 030b40be181ffbb3c3ae4a4911287c43261f5e4034781def69c
51608f372a02102
EvaluationElement = 03991df04e3e526d457065b6eafc855aa2fc4528c22d2b51
6a3c71227b1b488f44
Output = eca4df985f7c49b091c3ce4217be1f26cdc6a148b681ed1f1638d09dfd2
13e6e
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 4e7804245a743c59d624457677294e04a8bc4bdcd94f0d3bd54f568067489
d34
pkSm = 03b51a0af95c819b09ee80c2056cf0ab0551a5355266d3a0aaff90c3fe915
ed892
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = cee64d86fd20ab4caa264a26c0e3d42fb773b3173ba76f9588c9b14779bd
8d91
BlindedElement = 0222f5dba2da1ec7bd1086d0e04894ef1da1c11163daf376b2b
c76cc51edb16815
EvaluationElement = 02f2767135f75f69b257675b38f2bcd50338a655a5092166
3c8942ca61ea7d3c29
EvaluationProofC = ffa082fc9f9a287e7edc50e3ad879ee13aebd24b69124792b
df047c643f70af2
EvaluationProofS = b50907b2fa188b90aff3b25e1d9abb02e9e2c8bfdc525c61c
a008428940fca64
Output = c74d46cc93e578f7048bc6b852cd9bc1d9ebb90c586308f9202b9deedc8
94448
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 5c4b401063eff0bf242b4cd534a79bacfc2e715b2db1e7a3ad4ff8af1b24
daa2
BlindedElement = 02f84403d1ceb40a3668349f7c349f806d2c858785853324c66
7505018d13ee160
EvaluationElement = 0216d7d342ef50113244b444dfedaec78810959e40fef0a6
922658d44accb1e9c1
EvaluationProofC = f496e58818c25ffb386f22ceb57a83da1200612b67aaa0760
8b3375c25b297e0
EvaluationProofS = 3e67d1f6094a8012725dc63a0c2f4f870173b97a3daa03588
f777655a087fbbf
Output = 90a9f5ff4208a5505d1b7ed65eb233bb61b4c999ffa0d8cd1d98fb717b9
2fe28
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = f0c7822ba317fb5e86028c44b92bd3aedcf6744d388ca013ef33edd36930
4eda,3b9631be9f8b274d9aaf671bfb6a775229bf435021b89c683259773bc686956
b
BlindedElement = 02a840214a74345570dcadfc927e726901b257b447234fac509
0a1830295ca736c,039a5a8152abb0154b4d79a90486e358ea325980f0bf590524c4
460f700454238f
EvaluationElement = 025991aac0b0c79bb1185c0b1e64964656634dfcd755cdf5
da9ee52be0b5d5f742,03319e3baba8fa7f60dab49ef0ba68b7a85bccb5d4968643e
2f029b6c0826911d1
EvaluationProofC = 51b5ed453168480a2e95863cda1f4d28ad5bc91e8c9c75d78
8569aea1679794a
EvaluationProofS = 642087db120a2b3ce839f57041801f37cd4a6c05b69b327b8
77810293f7b09a8
Output = c74d46cc93e578f7048bc6b852cd9bc1d9ebb90c586308f9202b9deedc8
94448,90a9f5ff4208a5505d1b7ed65eb233bb61b4c999ffa0d8cd1d98fb717b92fe
28
~~~

## OPRF(P-384, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = ef1b52c12cdf43dc260bf5425a30cde7d708ec34b38dcfbdc2946d7baf525
361e797f6a98f1ebd80f64865f21cde1c6d
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 359073c015b92d15450f7fb395bf52c6ea98384c491fe4e4d423b59de7b0
df382902c13bdc9993d3717bda68fc080b99
BlindedElement = 02fa3115c21ffcacc09ca470729b725781f84333e217cfeec2b
8ba6a54ce492ede7ead3714c5b177427ef853effb1b5c24
EvaluationElement = 033a4bdea2693686e4ce467c8a5cdfc41b86ad20aaaa9bc1
6e75b59dbd41dab0bc9af0041e551ece3b4c9fb2315d8d1fa9
Output = a5a0ef3fb964a36097662d1258ef0f93b224ddd81a356c37d5dd05a885a
0b6722b90c1f5181637fece7ed180ba053da23bf35cef7a87dcba75562cb7a264001
8
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 21ece4f9b6ffd01ce82082545413bd9bb5e8f3c63b86ae88d9ce0530b01c
b1c23382c7ec9bdd6e75898e4877d8e2bc17
BlindedElement = 025fddc89a832089a59120df742acb34dba82b26afcae977961
57df238b5905c494a23c56b1f485cbbff78d31df7fa1492
EvaluationElement = 02f8b59813663e7965c219c113c560482cbea7ca4c412a0c
f3fd855ee7d543ae926d29ace85296f195f988be284b2347f6
Output = f2a0b355cae4ae2c717d0b48e39c0ee356db3ca446fddf85cddb74f397e
b85046da62d0d85d55d19d39dd9b68fcc39379ec6d3b93ba33909fcc96361d225cdd
e
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3
skSm = 67ee1c9e67566d87bfcca9e5dac4bfdb8bdd727c031133fac2aa9ba6c41e6
1e5f8fd401b5d76c7d54b15b15932797479
pkSm = 029b51b2ce9c499f2056e65e0f41d60960f9c4795c0cf94af273ce840c20b
e4cdf87690b6b121b37d399b49afcc2ec9ac3
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 102f6338df84c9602bfa9e7d690b1f7a173d07e6d54a419db4a6308f8b09
589e4283efb9cd1ee4061c6bf884e60a8774
BlindedElement = 02a1f41323e91a6ac9fbbb5b8e4c7c58a4c5bcbaa4195557182
cd59e826dc847f1e077de1d402ac92eafe322461fc0d582
EvaluationElement = 03af3164f8721a57931f92884b43c58ff0ed1be249f7e1c9
3033a5909f0ffc59ed3fea9452ec5c9cfb865b8bd2e65cd209
EvaluationProofC = 44108ca9b342f4d7e31a250aa9f41afb0de840e113dbb6bb8
2b5e6735aef18a20867a63628be6e109d2d687e1faa8888
EvaluationProofS = 270f1173bc6f916e21142096d23d17194edf844074922c287
a50182f87bbb5fc3a966c8851dd6799ec5cfe59c7063c7f
Output = 065094c66d66b6541aa1e09d99e2fdaac727356e9cd1c18275b7127be51
eb1ce7f37ad5924f7425d60828c2d1acc69bef40d11423bba8f9e34478e04c437fbe
0
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 8aec1d0c3d16afd032da7ba961449a56cec6fb918e932b06d5778ac7f67b
ecfb3e3869237f74106241777f230582e84a
BlindedElement = 02b3465d70f76de3eaf6ecb8080490288f741c622c06d023bd1
80a55a2e3e4eaad08533651f9d278a3f59cec8277780303
EvaluationElement = 03a53e01901893585437cd48a1eea1188fc8e9275a80cf43
370a451c476dae3b84ca8c7bf44fcac2fa3eeab933b25da0c3
EvaluationProofC = 5ebc467e78ae29f7d741221df0ee67285df72ec482fdc8e5b
de7e588b12fcba86f4f116c23ee6b32c0f38f2daac67e86
EvaluationProofS = 9e53e7e0494cc883e4984daf10a55819bbb5ce7e9005f143b
3dda88d8a35649269a4658a98c81c814097d15a3dcf4dbe
Output = 5f557169680da50500b5333a26bb2ba79256c0ecc351051d32cac540920
267a40b246deb286c9ecb0025dede808465f85d6a5e75aca61088533b306d8646c92
c
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 41fabd4722d92472d858051ce9ad1a533176a862c697b2c392aff2aeb77e
b20c2ae6ba52fe31e13e03bf1d9f39878b23,51171628f1d28bb7402ca4aea6465e2
67b7f977a1fb71593281099ef2625644aee0b6c5f5e6e01a2b052b3bd4caf539b
BlindedElement = 02d715dfce1a0724071fa8e530d79f7b234a31739a64166e0fe
21fa6fa0fe19e1ab5e468becca899f31e365c47f3efb2ef,028dfd0c7a38b4cb8477
cae34f041344fb44fc9e55bfa3cf55ab7b4764b74accc7b49c0ff09a524598033dad
1152fb3a1c
EvaluationElement = 03f9a8c81c108201888eb86348c6f80691d99425272972b5
bf41d3038af0eeb04d60edd9ea288625a7166a8c17cea0083f,02abb31980533dbf7
eb5fee0a8969089b3e16585a2cd41a34067592a2021b1b4ea3d1cef3e7c87a6f284c
0e45546c92d98
EvaluationProofC = f0f7bd2723c3460d5c5ab03092c6861fb34253470ef430dac
9aeac6ce48984b28d91178061cba02e3e911c4aa97229d5
EvaluationProofS = 19755db385ddd08064fdf8405897d1dea472688934088505e
89dcff91081fec1d2e37c1d4c5a9dddbdd358aa89f63b46
Output = 065094c66d66b6541aa1e09d99e2fdaac727356e9cd1c18275b7127be51
eb1ce7f37ad5924f7425d60828c2d1acc69bef40d11423bba8f9e34478e04c437fbe
0,5f557169680da50500b5333a26bb2ba79256c0ecc351051d32cac540920267a40b
246deb286c9ecb0025dede808465f85d6a5e75aca61088533b306d8646c92c
~~~

## OPRF(P-521, SHA-512)

### Base Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 016ee706f30ce7e15e4ffa3114c7d59a7b6f302d531ca60419be39d1cd43e
e13b1fc8398b7f63a900cdc49c6e99f65a74403db2fa739927a2ee288cff857d9d84
ecf
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 01b983705fcc9a39607288b935b0797ac6b3c4b2e848823ac9ae16b3a3b5
816be03432370deb7c3c17d9fc7cb4e0ce646e04e42d638e0fa7a434ed340772a8b5
d626
BlindedElement = 0301f0a8c68e58f5571bd39fe3b0b2aa055a8c34e3d68ba0d2e
d177db0bc7575d477ed8f557596feb5ac568fe738eee8cff7dcb56dc78f52bf381c0
912e0e84b5a3f5b
EvaluationElement = 0200d7b1131aa9f8c365de7bd7903738f61bdecfaada375a
ba3905bdaad1301c7cd537f69abff04140ccca29a4c46cb4a036160e55a9621210b3
71d84646b0199571fa
Output = 61eea8fedfa9338dd22fac279f1f3f9e96693919c59ea3918c7a441115e
6bdecb1d05b5da55d4024858c92d3911a81d4eca362123b2911e5dc58591bf7be29c
7
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01a03b1096b0316bc8567c89bd70267d35c8ddcb2be2cdc867089a2eb5cf
471b1e6eb4b043b9644c8539857abe3a2022e9c9fd6a1695bbabe8add48bcd149ff3
b841
BlindedElement = 030099c35342a43221c6e03debfb17bad71b62e04c9242aa6e9
f2f915163ef4f5b8b7fe1740a4d636c36bd5c73ca39c69992dc7f6dff8f232125efc
22af4df8352fea2
EvaluationElement = 0300ceeba6751486eecc479ab2259e3a57c13b0710f61c82
87acad60624974b76ea242dbcae3a9daad1bdc9c49012c8d8b384d510980cc1ef8fa
8d10502748ce63d93f
Output = 6682273a5199b2454a706cac557008e2264580ac39b6995e1f47130b985
d1015de7713d3bdb121212a68de2ece73bf72e41738a01c23428753c44e3dd39b5de
3
~~~

### Verifiable Mode

~~~
seed = a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a
3a3
skSm = 0017674057e06c5e3e8a331f2dc3558540701c9cd0f4c19126d5972af6a01
447b312d05a06dab3e9e07c891d749444c27ede0897ad42aea03b887eb5db93e3f29
a86
pkSm = 0201ee4e2eaa74728f577f4bb282c5440cd454fdee1d79b15a36d34b5e5a1
25e3ccc0f99e32cc0a6a15b5652a0c8a424860c6753f685d0e1e150ceba24ca3386f
29216
~~~

#### Test Vector 1, Batch Size 1

~~~
Input = 00
Info = 7465737420696e666f
Blind = 00bbb82117c88bbd91b8954e16c0b9ceed3ce992b198be1ebfba9ba970db
d75beefbfc6d056b7f7ba1ef79f4facbf2d912c26ce2ecc5bb8d66419b379952e96b
d6f5
BlindedElement = 0200357f949a0a0bdfeb682734dbdeb778f3845045617b21436
27753332e2e75458ab183b12635c75e19afaf56981e7755803026842db1b22fa42c8
61413d07ff86545
EvaluationElement = 0201d636bac3f77c1091b337daae32259a3eacd57e3c0fb1
444fe5ce22af6acdcef4a46a2b5e169aa8d0e26ec2a3621c15dd366ba1978dae761c
1ef3dac63c60cbee88
EvaluationProofC = 011ebe27ebc79e5679b643c6b3a51333499c7abee86c09218
1c0a8e7e539e0ba30b1c128666708c753696ace2aa789c4975b0b80d6241a1dafe85
c39a7338d1e20d0
EvaluationProofS = 0131c8a81b5f64209f8fe53e8c6a00789a893f20596198e25
21275e05d92529808e9f54030fc8be2ce78c6df0d29e6fd7d8e623e0ccc7b19b1944
93dacd2a4eb3a32
Output = c51295e2a03ba59f1538734316e0d70dd81f95daba2f7b5ac4906c56ce8
79d6cef8f583433c981a182a52dd568811b073f65fc1124941f344cc9dd3b3880f29
5
~~~

#### Test Vector 2, Batch Size 1

~~~
Input = 5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 009055c99bf9591cb0eab2a72d044c05ca2cc2ef9b609a38546f74b6d688
f70cf205f782fa11a0d61b2f5a8a2a1143368327f3077c68a1545e9aafbba6a90dc0
d40a
BlindedElement = 030185e431f056e75ba7fac49da70790031daa333d16f05e1de
471e24afe0ed985c770ce77bd1bebec527e9a76feecc6afd92c5fd00481ba7fb843d
2aab52337cb716e
EvaluationElement = 02000859e1abc2ed28086b854ec5ae72311244fdeedf81d7
69af6a6f2c83f00fa48df1f1a0c0b6fac84cc654b7757ac042107a6b3043e483bb3b
74de5d6c301b20e8f6
EvaluationProofC = 01629dd5af14c7414801d879b1018ce06bcc5c5d0a64ca422
b76aaa531c8ecca630919fb4b51fa60fdc215f73e67e8d617d55ca6a227343d434d5
e0f487567f85bfa
EvaluationProofS = 016959443267bb7d9a5c5e5b1c4d20026394b4edaca7dfbc1
aa3b3c2020cf99579cf276c0e84f0cb5a820226fa3b81d42de2db39d8412642e7042
8e485a61ee9d760
Output = 7462f460340a52f7b7609c5e1c5e2d5334d43da7631cb549bb65163a05d
1b2e936669e52e66c92da4b2e24fff3c118c62787577c01d2885567b476c13011057
1
~~~

#### Test Vector 3, Batch Size 2

~~~
Input = 00,5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
Info = 7465737420696e666f
Blind = 01c6cf092d80c7cf2cb55388d899515238094c800bdd9c65f71780ba85f5
ae9b4703e17e559ca3ccd1944f9a70536c175f11a827452672b60d4e9f89eba28104
6e29,00cba1ba1a337759061965a423d9d3d6e1e1006dc8984ad28a4c93ecfc36fc2
171046b3c4284855cfa2434ed98db9e68a597db2c14728fade716a6a82d600444b26
e
BlindedElement = 0301978860af75cd69acbc93e8c9fc530e5d2b2208da42c65bf
e079f0f6e0b3fc6080556c10739271d2a8fe578409d4fa9b19ef0484d9c15451c4e7
0501e31da7608cb,0200e30565c3d7e02c822762f25db4c872811adb2cbfbad92b04
291bc8c476d0546d1c5ecf5c58ff06b8d19aad8eca9e5f1a80ff8e981ebc490b0cfb
d5d499b47bad8e
EvaluationElement = 0300abdee910f144c3be460e724c11626e1f9986f72e2c43
3a9c4dad2ef6fcb9249c9a5036334ba88b0892462b6f8ad419c38cc259b0c774a9bd
0c4d545d0914413ea2,02019696f91dcc178bbe6b97f822cdc4052f9b94852ff6023
f6068848f867df40e54a5f1525e7fafa383e82fe36bf3c74427b51903032d0f89876
05bf24ee003f37693
EvaluationProofC = 008fa896b69c1efc4e9c6bdfd0b149444532d5ba3bfd957cf
7cd71c374d3a1cca25f17b60616164377b0734243bc878e17d3ecab36b3e3565b5c6
218dae92d40c0be
EvaluationProofS = 018707381f6f4b0153044737030b5d9851c15609532da8932
c1fa1f4901dba05a4118d25142344f9ea1465c907eb13d908a45d8b98265eac48819
a04cae859b0643a
Output = c51295e2a03ba59f1538734316e0d70dd81f95daba2f7b5ac4906c56ce8
79d6cef8f583433c981a182a52dd568811b073f65fc1124941f344cc9dd3b3880f29
5,7462f460340a52f7b7609c5e1c5e2d5334d43da7631cb549bb65163a05d1b2e936
669e52e66c92da4b2e24fff3c118c62787577c01d2885567b476c130110571
~~~
"#;

macro_rules! parse {
    ( $v:ident, $s:expr ) => {
        parse_default!($v, $s, vec![])
    };
}

macro_rules! parse_default {
    ( $v:ident, $s:expr, $d:expr ) => {
        match decode(&$v, $s) {
            Some(x) => x,
            None => $d,
        }
    };
}

macro_rules! json_to_test_vectors {
    ( $v:ident, $cs:expr, $mode:expr ) => {
        $v[$cs][$mode]
            .members()
            .map(|x| populate_test_vectors(&x))
            .collect::<Vec<VOPRFTestVectorParameters>>()
    };
}

#[test]
fn test_print_json() -> () {
    let json = rfc_to_json(OPRF_TEST_VECTORS);
    println!("{}", &json);
}

fn decode(values: &JsonValue, key: &str) -> Option<Vec<u8>> {
    values[key]
        .as_str()
        .and_then(|s| hex::decode(&s.to_string()).ok())
}

fn decode_vec(values: &JsonValue, key: &str) -> Option<Vec<Vec<u8>>> {
    let s = values[key].as_str().unwrap();
    match s.contains(',') {
        true => Some(
            s.split(',')
                .map(|x| hex::decode(&x.to_string()).unwrap())
                .collect(),
        ),
        false => Some(vec![hex::decode(&s.to_string()).unwrap()]),
    }
}

fn populate_test_vectors(values: &JsonValue) -> VOPRFTestVectorParameters {
    VOPRFTestVectorParameters {
        seed: decode(&values, "seed").unwrap(),
        sksm: decode(&values, "skSm").unwrap(),
        input: decode_vec(&values, "Input").unwrap(),
        info: parse!(values, "Info"),
        blind: decode_vec(&values, "Blind").unwrap(),
        blinded_element: decode_vec(&values, "BlindedElement").unwrap(),
        evaluation_element: decode_vec(&values, "EvaluationElement").unwrap(),
        output: decode_vec(&values, "Output").unwrap(),
    }
}

#[test]
fn tests() -> Result<(), InternalError> {
    struct Ristretto255Sha512;
    impl CipherSuite for Ristretto255Sha512 {
        type Group = RistrettoPoint;
        type Hash = Sha512;
    }

    let rfc = json::parse(rfc_to_json(OPRF_TEST_VECTORS).as_str()).expect("Could not parse json");

    let ristretto_base_tvs = json_to_test_vectors!(
        rfc,
        String::from("ristretto255, SHA-512"),
        String::from("Base")
    );

    test_blind::<Ristretto255Sha512>(&ristretto_base_tvs)?;
    test_evaluate::<Ristretto255Sha512>(&ristretto_base_tvs)?;
    test_finalize::<Ristretto255Sha512>(&ristretto_base_tvs)?;

    #[cfg(feature = "p256")]
    {
        struct P256Sha256;
        impl CipherSuite for P256Sha256 {
            type Group = p256_::ProjectivePoint;
            type Hash = sha2::Sha256;
        }

        let p256_base_tvs =
            json_to_test_vectors!(rfc, String::from("P-256, SHA-256"), String::from("Base"));

        test_blind::<P256Sha256>(&p256_base_tvs)?;
        test_evaluate::<P256Sha256>(&p256_base_tvs)?;
        test_finalize::<P256Sha256>(&p256_base_tvs)?;
    }

    Ok(())
}

// Tests input -> blind, blinded_element
fn test_blind<CS: CipherSuite>(tvs: &[VOPRFTestVectorParameters]) -> Result<(), InternalError> {
    for parameters in tvs {
        let mut rng = CycleRng::new(parameters.blind[0].to_vec());
        let (client, blinded_element) =
            NonVerifiableClient::<CS>::blind(&parameters.input[0], &mut rng)?;

        assert_eq!(
            &parameters.blind[0],
            &CS::Group::scalar_as_bytes(client.get_blind()).to_vec()
        );
        assert_eq!(
            &parameters.blinded_element[0],
            &blinded_element.to_arr().to_vec()
        );
    }
    Ok(())
}

// Tests sksm, blinded_element -> evaluation_element
fn test_evaluate<CS: CipherSuite>(tvs: &[VOPRFTestVectorParameters]) -> Result<(), InternalError> {
    for parameters in tvs {
        let server = NonVerifiableServer::<CS>::new_with_key(&parameters.sksm).unwrap();
        let evaluation_element = server.evaluate(
            CS::Group::from_element_slice(GenericArray::from_slice(&parameters.blinded_element[0]))
                .unwrap(),
            &parameters.info,
        )?;

        assert_eq!(
            &parameters.evaluation_element[0],
            &evaluation_element.to_arr().to_vec()
        );
    }
    Ok(())
}

// Tests input, blind, evaluation_element -> output
fn test_finalize<CS: CipherSuite>(tvs: &[VOPRFTestVectorParameters]) -> Result<(), InternalError> {
    for parameters in tvs {
        let client = NonVerifiableClient::<CS>::from_data_and_blind(
            &parameters.input[0],
            &<CS::Group as Group>::from_scalar_slice(&GenericArray::clone_from_slice(
                &parameters.blind[0],
            ))
            .unwrap(),
        );

        let output = client.finalize(
            <CS::Group as Group>::from_element_slice(GenericArray::from_slice(
                &parameters.evaluation_element[0],
            ))?,
            &parameters.info,
        )?;

        assert_eq!(&parameters.output[0], &output.to_vec());
    }
    Ok(())
}
