use frost_dalek::{
    compute_message_hash, generate_commitment_share_lists, DistributedKeyGeneration, Parameters,
    Participant, SignatureAggregator,
};
use rand_core::OsRng;
use solana_sdk::{pubkey::Pubkey, signature::Signature};

#[allow(deprecated)]
fn main() {
    // This is agreed upon a priori
    let params = Parameters { n: 5, t: 3 };
    const ALICE_INDEX: u32 = 0;
    const BOB_INDEX: u32 = 1;
    const CAROL_INDEX: u32 = 2;
    #[allow(unused)]
    const DAVE_INDEX: u32 = 3;
    #[allow(unused)]
    const ERIC_INDEX: u32 = 4;

    // These are generated independently on different devices in private
    // The coefficients here are the private keys and must not be shared
    let (alice, alice_coeffs_private) = Participant::new(&params, 0);
    let (bob, bob_coeffs_private) = Participant::new(&params, 1);
    let (carol, carol_coeffs_private) = Participant::new(&params, 2);
    let (dave, dave_coeffs_private) = Participant::new(&params, 3);
    let (eric, eric_coeffs_private) = Participant::new(&params, 4);

    // These are public and should be shared.
    let participants = [alice, bob, carol, dave, eric];

    // For example, bob could verify alice's zk proof
    // (pretend we are on bob's machine and he has received alice's zkp)
    {
        let bobs_alice_copy = &participants[ALICE_INDEX as usize];
        assert!(bobs_alice_copy
            .proof_of_secret_key
            .verify(&ALICE_INDEX, bobs_alice_copy.public_key().unwrap())
            .is_ok());
    }

    // These are private and should not be shared.
    let participants_private = [
        alice_coeffs_private,
        bob_coeffs_private,
        carol_coeffs_private,
        dave_coeffs_private,
        eric_coeffs_private,
    ];

    // Now all participants start distributed key generation
    // This is to be done on different devices in private,
    // although the shares produced are to be distributed.
    let shares: [DistributedKeyGeneration<_>; 5] = std::array::from_fn(|i| {
        let mut other_participants = participants.to_vec();
        other_participants.remove(i);
        DistributedKeyGeneration::<_>::new(
            &params,
            &(i as u32),
            &participants_private[i],
            &mut other_participants,
        )
        .unwrap()
    });

    // Now we distribute these shares and each peer builds their group keypair
    let distributed_kps: [DistributedKeypair<_, _>; 5] = std::array::from_fn(|slf| {
        // Get secret shares
        let other_shares = (0..5)
            .flat_map(|peer| {
                if peer != slf {
                    // In a real setting, we wouldn't share all secret shares with all peers
                    // This emulates that but technically their_secret_shares contains all secret shares
                    let share_idx = if slf <= peer { slf } else { slf - 1 };
                    let secret_shares = shares[peer].their_secret_shares().unwrap();
                    Some(secret_shares[share_idx].clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Start round two
        let round_two = shares[slf].clone().to_round_two(other_shares).unwrap();

        // Finalize
        let (group_key, secret_key) = round_two
            .finish(participants[slf].public_key().unwrap())
            .unwrap();

        DistributedKeypair {
            group_key,
            secret_key,
        }
    });

    // Try group signing 3/5
    // 1: Group key is the same for all
    let group_key = distributed_kps[0].group_key;
    // 2: define context and message, and get hash
    let context = b"shadowy meeting";
    let message = b"we are shadowy super coders; in the darkness we linger";
    let message_hash = compute_message_hash(&context[..], &message[..]);
    // 3: Build aggregator, and decide who is going to sign
    let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);
    let signer_indices = [ALICE_INDEX, BOB_INDEX, CAROL_INDEX];
    // 4: Get commitment share list
    let commitment_share_list =
        signer_indices.map(|s| generate_commitment_share_lists(&mut OsRng, s, 1));
    let mut pub_share_list = Vec::with_capacity(signer_indices.len());
    let mut sec_share_list = Vec::with_capacity(signer_indices.len());
    for (public, secret) in commitment_share_list {
        pub_share_list.push(public);
        sec_share_list.push(secret);
    }
    // 5: Update aggregator with signer's commitment shares
    for s in signer_indices {
        // Signer's secret key
        let signer_sk = &distributed_kps[s as usize].secret_key;

        // Getseckey
        let signer_pk = signer_sk.to_public();

        // Include signer
        aggregator.include_signer(s, pub_share_list[s as usize].commitments[0], signer_pk);
    }

    // 6: Aggregate signatures
    for s in signer_indices {
        // Signature produced and sent to aggregator to be included
        let signers = aggregator.get_signers();
        let signature = distributed_kps[s as usize]
            .secret_key
            .sign(
                &message_hash,
                &group_key,
                &mut sec_share_list[s as usize],
                0, // only one commitment for this demo
                signers,
            )
            .unwrap();

        // Include signature in aggregator
        aggregator.include_partial_signature(signature);
    }

    // Finalize
    let aggregator = aggregator.finalize().unwrap();
    let threshold_signature = aggregator.aggregate().unwrap();

    // Verify
    assert!(threshold_signature
        .verify(&group_key, &message_hash)
        .is_ok());

    //
    //
    // Now we go to solana land
    //
    //

    // Group pubkey and signature
    let pubkey = Pubkey::new_from_array(group_key.to_bytes());
    println!("gk = {:?}", group_key.to_bytes().eq(pubkey.as_ref()));
    let signature = Signature::new(&threshold_signature.to_bytes());
    println!(
        "tsig = {:?}",
        threshold_signature.to_bytes().eq(signature.as_ref())
    );

    // Check message
    assert!(signature.verify(pubkey.as_ref(), message_hash.as_ref()));

    println!("success! :D");
}

pub struct DistributedKeypair<G, S> {
    group_key: G,
    secret_key: S,
}
