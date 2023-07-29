use std::ops::Range;

use frost_dalek::{compute_message_hash, generate_commitment_share_lists, keygen::Coefficients, DistributedKeyGeneration, Parameters, Participant, SignatureAggregator};
use rand_core::OsRng;
use solana_sdk::{pubkey::Pubkey, signature::Signature};

fn main() {
    // This is agreed upon a priori
    const GROUP_SIZE: u32 = 500;
    const GROUP_USIZE: usize = GROUP_SIZE as usize;
    const THRESHOLD: u32 = 300;
    let params = Parameters { n: GROUP_SIZE, t: THRESHOLD };

    const SIGNER_INDICES: Range<u32> = 0..THRESHOLD;

    // These are generated independently on different devices in private
    // The coefficients here (second element) are the private keys and must not be shared
    // (We will split them in the next steps)
    let participants_pubs_and_secs: [(Participant, Coefficients); GROUP_USIZE] = core::array::from_fn(|i| Participant::new(&params, i as u32));
    println!("generated pubs and secrets");

    // These are public and should be shared. (pubs are clonable)
    let participants: [Participant; GROUP_USIZE] = core::array::from_fn(|i| participants_pubs_and_secs[i].0.clone());

    // For example, bob could verify alice's zk proof
    // (pretend we are on bob's machine and he has received alice's zkp)
    {
        const ALICE_INDEX: u32 = 0;
        let bobs_alice_copy = &participants[ALICE_INDEX as usize];
        assert!(bobs_alice_copy.proof_of_secret_key.verify(&ALICE_INDEX, bobs_alice_copy.public_key().unwrap()).is_ok());
    }
    // Let's verify them all
    for (p, i) in participants.iter().zip(0..) {
        assert!(p.proof_of_secret_key.verify(&i, p.public_key().unwrap()).is_ok())
    }
    println!("verified exchanged pubs and zkps");

    // These are private and should not be shared.
    let participants_private: [Coefficients; GROUP_USIZE] = participants_pubs_and_secs.map(|(_public, secret)| secret);

    // Now all participants start distributed key generation
    // This is to be done on different devices in private,
    // although the shares produced are to be distributed.
    let shares: [DistributedKeyGeneration<_>; GROUP_USIZE] = std::array::from_fn(|i| {
        let mut other_participants = participants.to_vec();
        other_participants.remove(i); // remove our pub from list
        DistributedKeyGeneration::<_>::new(
            &params,
            &(i as u32),
            &participants_private[i], // we only use our own secret!
            &mut other_participants,  // pubs of all other participants
        )
        .unwrap()
    });

    // Now we distribute these shares and each peer builds their group keypair
    let distributed_kps: [DistributedKeypair<_, _>; GROUP_USIZE] = std::array::from_fn(|slf| {
        // Get secret shares
        let other_shares = (0..GROUP_USIZE)
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
        let (group_key, secret_key) = round_two.finish(participants[slf].public_key().unwrap()).unwrap();

        DistributedKeypair { group_key, secret_key }
    });
    println!("generated distributed keypairs");

    // Try group signing
    // 1: Group key is the same for all
    let group_key = distributed_kps[0].group_key;
    // 2: define context and message, and get hash
    let context = b"shadowy meeting";
    let message = b"we are shadowy super coders; in the darkness we linger";
    let message_hash = compute_message_hash(&context[..], &message[..]);
    // 3: Build aggregator, and decide who is going to sign
    let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);
    // 4: Get commitment share list
    let commitment_share_list = SIGNER_INDICES.map(|s| generate_commitment_share_lists(&mut OsRng, s, 1));
    let mut pub_share_list = Vec::with_capacity(SIGNER_INDICES.len());
    let mut sec_share_list = Vec::with_capacity(SIGNER_INDICES.len());
    for (public, secret) in commitment_share_list {
        pub_share_list.push(public);
        sec_share_list.push(secret);
    }
    // 5: Update aggregator with signer's commitment shares
    for s in SIGNER_INDICES {
        // Signer's secret key
        let signer_sk = &distributed_kps[s as usize].secret_key;

        // Getseckey
        let signer_pk = signer_sk.to_public();

        // Include signer
        aggregator.include_signer(s, pub_share_list[s as usize].commitments[0], signer_pk);
    }

    // 6: Aggregate signatures
    for s in SIGNER_INDICES {
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
    println!("aggregated signatures");

    // Finalize
    let aggregator = aggregator.finalize().unwrap();
    let threshold_signature = aggregator.aggregate().unwrap();
    println!("finalized signature");

    // Verify
    assert!(threshold_signature.verify(&group_key, &message_hash).is_ok());

    //
    //
    // Now we go to solana land
    //
    //

    // Group pubkey and signature
    let pubkey = Pubkey::new_from_array(group_key.to_bytes());
    assert_eq!(group_key.to_bytes(), pubkey.as_ref(), "{:?} != {:?}", group_key.to_bytes(), pubkey.as_ref());
    #[allow(deprecated)]
    let signature = Signature::new(&threshold_signature.to_bytes());
    assert_eq!(threshold_signature.to_bytes(), signature.as_ref(), "{:?} != {:?}", threshold_signature.to_bytes(), signature.as_ref());

    // Check message
    assert!(signature.verify(pubkey.as_ref(), message_hash.as_ref()));
    println!("signature verified");

    println!("{THRESHOLD} of {GROUP_SIZE} signature success! :D");
}

pub struct DistributedKeypair<G, S> {
    group_key: G,
    secret_key: S,
}
