use dep::std;
use dep::std::merkle::compute_merkle_root;
use dep::std::hash::poseidon::bn254 as poseidon;
use dep::std::hash::pedersen_hash;

fn main(private_inputs: PrivateIn, signal_hash: pub Field, external_nullifier: pub Field, root: pub Field, nullifier_hash: pub Field) {
    let circuit_output = semaphore(private_inputs, signal_hash, external_nullifier);
    assert(root == circuit_output[0]);
    assert(nullifier_hash == circuit_output[1]);
}

struct PrivateIn {
    identity_nullifier: Field, identity_trapdoor: Field, leaf_index: Field, tree_siblings: [Field;30]
}

struct PublicIn {
    signal_hash: Field, external_nullifier: Field
}

fn calculate_secret(identity_nullifier: Field, identity_trapdoor: Field) -> Field {
    poseidon::hash_2([identity_nullifier, identity_trapdoor])
}

fn calculate_identity_commitment(secret: Field) -> Field {
    poseidon::hash_1([secret])
}

fn calculate_nullifier_hash(external_nullifier: Field, identity_nullifier: Field) -> Field {
    poseidon::hash_2([external_nullifier, identity_nullifier])
}

fn semaphore(private_inputs: PrivateIn, signal_hash: Field, external_nullifier: Field) -> [Field;2] {
    let secret = calculate_secret(private_inputs.identity_nullifier, private_inputs.identity_trapdoor);
    let leaf = calculate_identity_commitment(secret);

    let nullifier_hash = calculate_nullifier_hash(external_nullifier, private_inputs.identity_nullifier);
    let root = compute_merkle_root(leaf, private_inputs.leaf_index, private_inputs.tree_siblings);
    let _signal_hash_squared = signal_hash * signal_hash;
    [root, nullifier_hash]
}

// to see output run like this
//  nargo test --show-output test_should_pass
#[test]
fn test_should_pass() {
    // private inouts, can just pick
    let identity_nullifier = 11222333444;
    let identity_trapdoor = 555666777888;

    // private values, determinde by merkle tree
    let leaf_index = 1;
    let identity_commitment = poseidon::hash_1([poseidon::hash_2([identity_nullifier, identity_trapdoor])]);

    // public values externally generated
    let external_nullifier = 42;

    // this is a topic, can he any value
    let signal_hash = 99;

    // consistency should be checked by the smart contract against the msg hash
    // Construct the merkle tree
    /*
    root |             0
         |            / \
    l2   |        0           1 
         |       / \        
          / \
    l1   |     0     1     0     0
         |    / \   / \   / \   / \
    l0   |   [0, 1, 0, 0, 0, 0, 0, 0]
              0  1  2  3  4  5  6  7
    */
    let mut tree_siblings: [Field;30] = [0; 30];
    let mut previous_node = 0;

    for i in 1..30 {
        let node = pedersen_hash([previous_node, previous_node + 1]);
        tree_siblings[i] = node;
        previous_node = node;
    }

    let root = compute_merkle_root(identity_commitment, leaf_index, tree_siblings);

    let nullifier_hash = poseidon::hash_2([external_nullifier, identity_nullifier]);

    let private_inputs = PrivateIn { identity_nullifier, identity_trapdoor, leaf_index, tree_siblings };

    std::println("private_inputs");
    std::println(private_inputs);
    std::println("signal_hash");
    std::println(signal_hash);
    std::println("external_nullifier");
    std::println(external_nullifier);
    std::println("root");
    std::println(root);
    std::println("nullifier_hash");
    std::println(nullifier_hash);
    main(private_inputs, signal_hash, external_nullifier, root, nullifier_hash);
}



#[test(should_fail)]
fn test_wrong_identity_commitment() {
    /*
    The prover does not know a correct identity commitment
    */
    // private inouts, can just pick
    let correct_identity_nullifier = 11222333444;
    let correct_identity_trapdoor = 555666777888;

    // private values, determinde by merkle tree
    let correct_leaf_index = 1;
    let correct_identity_commitment = poseidon::hash_1([poseidon::hash_2([correct_identity_nullifier, correct_identity_trapdoor])]);

    // public values externally generated
    let external_nullifier = 42;

    // this is a topic, can he any value
    let signal_hash = 99;

    // consistency should be checked by the smart contract against the msg hash
    let mut correct_tree_siblings: [Field;30] = [0; 30];
    let mut previous_node = 0;

    for i in 1..30 {
        let node = pedersen_hash([previous_node, previous_node + 1]);
        correct_tree_siblings[i] = node;
        previous_node = node;
    }

    let correct_root = compute_merkle_root(correct_identity_commitment, correct_leaf_index, correct_tree_siblings);

    // these are the wrong "private key pairs that go into the private inputs of the circuits"
    let wrong_identity_nullifier = 42;
    let wrong_identity_trapdoor = 21;
    let wrong_nullifier_hash = poseidon::hash_2([external_nullifier, wrong_identity_nullifier]);

    let private_inputs = PrivateIn {
        identity_nullifier: wrong_identity_nullifier,
        identity_trapdoor: wrong_identity_trapdoor,
        leaf_index: correct_leaf_index,
        tree_siblings: correct_tree_siblings
    };

    main(private_inputs, signal_hash, external_nullifier, correct_root, wrong_nullifier_hash);
}
