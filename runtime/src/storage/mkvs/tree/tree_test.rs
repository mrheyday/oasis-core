use std::{collections::HashSet, fs::File, io::BufReader, iter, iter::FromIterator, path::Path};

use crate::storage::mkvs::{
    interop::{Driver, ProtocolServer},
    tests,
    tree::*,
    Iterator, LogEntry, LogEntryKind, WriteLog, MKVS,
};

const INSERT_ITEMS: usize = 1000;
const ALL_ITEMS_ROOT: &str = "2187c55627819b60069888ba86f83dc2a9f50c827624b0e31e31261806300ede";

const LONG_KEY: &str = "Unlock the potential of your data without compromising security or privacy";
const LONG_VALUE: &str = "The platform that puts data privacy first. From sharing medical records, to analyzing personal financial information, to training machine learning models, the Oasis platform supports applications that use even the most sensitive data without compromising privacy or performance.";
const ALL_LONG_ITEMS_ROOT: &str =
    "d829bb244a709bacf33bc2d8b4a016592e5310a10910aa980ef91cb3b4347dcb";

pub fn generate_key_value_pairs_ex(prefix: String, count: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(count);
    let mut values: Vec<Vec<u8>> = Vec::with_capacity(count);

    for i in 0..count {
        keys.push(format!("{}key {}", prefix, i).into_bytes());
        values.push(format!("{}value {}", prefix, i).into_bytes());
    }

    (keys, values)
}
fn generate_key_value_pairs() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    generate_key_value_pairs_ex("".to_string(), INSERT_ITEMS)
}

fn generate_long_key_value_pairs() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(LONG_KEY.len());
    let mut values: Vec<Vec<u8>> = Vec::with_capacity(LONG_KEY.len());

    for i in 0..LONG_KEY.len() {
        keys.push(LONG_KEY[0..i + 1].to_string().into_bytes());
        values.push(LONG_VALUE.to_string().into_bytes());
    }

    (keys, values)
}

#[test]
fn test_basic() {
    let mut tree = OverlayTree::new(
        Tree::builder()
            .with_root_type(RootType::State)
            .build(Box::new(NoopReadSyncer)),
    );

    let key_zero = b"foo";
    let value_zero = b"bar";
    let value_zero_alt = b"baz";
    let key_one = b"moo";
    let value_one = b"foo";
    let value_one_alt = b"boo";

    // Insert two keys and check committed tree.
    assert_eq!(tree.insert(key_zero, value_zero).expect("insert"), None);
    assert_eq!(tree.cache_contains_key(key_zero), true);
    assert_eq!(tree.cache_contains_key(key_one), false);
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero);

    assert_eq!(
        tree.insert(key_zero, value_zero)
            .expect("insert")
            .expect("insert_some")
            .as_slice(),
        value_zero
    );
    assert_eq!(tree.cache_contains_key(key_zero), true);
    assert_eq!(tree.cache_contains_key(key_one), false);
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero);

    let (log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "db67c0572006673b488342a45e6590a75e8919265e6da706c80c6b2776017aa7"
    );
    assert_eq!(
        log,
        [LogEntry {
            key: key_zero.to_vec(),
            value: Some(value_zero.to_vec()),
        }]
        .to_vec()
    );
    assert_eq!(log[0].kind(), LogEntryKind::Insert);

    // Check overwriting modifications.
    assert_eq!(tree.insert(key_one, value_one).expect("insert"), None);
    assert_eq!(tree.cache_contains_key(key_zero), true);
    assert_eq!(tree.cache_contains_key(key_one), true);
    let value = tree.get(key_one).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_one);

    assert_eq!(
        tree.insert(key_zero, value_zero_alt)
            .expect("insert")
            .expect("insert_some")
            .as_slice(),
        value_zero
    );
    assert_eq!(tree.cache_contains_key(key_zero), true);
    assert_eq!(tree.cache_contains_key(key_one), true);
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);
    let value = tree.get(key_one).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_one);

    assert_eq!(
        tree.remove(key_one)
            .expect("remove")
            .expect("remove_some")
            .as_slice(),
        value_one
    );
    assert_eq!(tree.remove(key_one).expect("remove"), None);
    assert_eq!(tree.cache_contains_key(key_zero), true);
    assert_eq!(tree.cache_contains_key(key_one), false);
    assert_eq!(None, tree.get(key_one).expect("get"));
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);

    assert_eq!(tree.insert(key_one, value_one_alt).expect("insert"), None);
    assert_eq!(tree.cache_contains_key(key_zero), true);
    assert_eq!(tree.cache_contains_key(key_one), true);
    let value = tree.get(key_zero).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_zero_alt);
    let value = tree.get(key_one).expect("get").expect("get_some");
    assert_eq!(value.as_slice(), value_one_alt);

    assert_eq!(
        tree.insert(key_zero, value_zero)
            .expect("insert")
            .expect("insert_some")
            .as_slice(),
        value_zero_alt
    );
    assert_eq!(
        tree.insert(key_one, value_one)
            .expect("insert")
            .expect("insert_some")
            .as_slice(),
        value_one_alt
    );

    // Tree now has key_zero and key_one and should hash as if the mangling didn't happen.
    let (log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "e627581db43e18410a52793e662e4f21ae6a4fca14e16915a85ec4c3e3e41a13"
    );
    // Order of transactions in writelog is arbitrary.
    assert_eq!(
        HashSet::<LogEntry>::from_iter(log.clone().into_iter()),
        HashSet::<LogEntry>::from_iter(
            [
                LogEntry {
                    key: key_one.to_vec(),
                    value: Some(value_one.to_vec()),
                },
                LogEntry {
                    key: key_zero.to_vec(),
                    value: Some(value_zero.to_vec()),
                }
            ]
            .to_vec()
            .into_iter()
        )
    );
    assert_eq!(log[0].kind(), LogEntryKind::Insert);
    assert_eq!(log[1].kind(), LogEntryKind::Insert);

    tree.remove(key_one).expect("remove");
    assert_eq!(true, tree.get(key_one).expect("get").is_none());

    let (log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
    assert_eq!(
        format!("{:?}", hash),
        "db67c0572006673b488342a45e6590a75e8919265e6da706c80c6b2776017aa7"
    );
    assert_eq!(
        log,
        [LogEntry {
            key: key_one.to_vec(),
            value: None,
        }]
        .to_vec()
    );
    assert_eq!(log[0].kind(), LogEntryKind::Delete);
    tree.remove(key_zero).expect("remove");
    assert_eq!(tree.cache_contains_key(key_zero), false);
    assert_eq!(tree.cache_contains_key(key_one), false);
}

#[test]
fn test_long_keys() {
    let mut tree = Tree::builder()
        .with_root_type(RootType::State)
        .build(Box::new(NoopReadSyncer));

    // First insert keys 0..n and remove them in order n..0.
    let mut roots: Vec<Hash> = Vec::new();
    let (keys, values) = generate_long_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
        roots.push(hash);
    }

    for i in 0..keys.len() {
        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), true);
        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    assert_eq!(format!("{:?}", roots[roots.len() - 1]), ALL_LONG_ITEMS_ROOT);

    for i in (1..keys.len()).rev() {
        tree.remove(keys[i].as_slice()).expect("remove");

        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), false);
        assert_eq!(None, tree.get(keys[i].as_slice()).expect("get"));

        let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
        assert_eq!(hash, roots[i - 1]);
    }

    tree.remove(keys[0].as_slice()).expect("remove");

    let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());
}

#[test]
fn test_empty_keys() {
    let mut tree = Tree::builder()
        .with_root_type(RootType::State)
        .build(Box::new(NoopReadSyncer));

    fn test_empty_key(tree: &mut Tree) {
        let empty_key = b"";
        let empty_value = b"empty value";

        assert_eq!(tree.cache_contains_key(empty_key), false);
        tree.insert(empty_key, empty_value).expect("insert");

        assert_eq!(tree.cache_contains_key(empty_key), true);
        let value = tree.get(empty_key).expect("get").expect("get_some");
        assert_eq!(empty_value, value.as_slice());

        tree.remove(empty_key).expect("remove");

        assert_eq!(tree.cache_contains_key(empty_key), false);
        assert_eq!(None, tree.get(empty_key).expect("get"));
    }

    fn test_zeroth_discriminator_bit(tree: &mut Tree) {
        let key1 = &[0x7f as u8, 0xab];
        let key2 = &[0xff as u8, 0xab];
        let value1 = b"value 1";
        let value2 = b"value 2";

        tree.insert(key1, value1).expect("insert");
        tree.insert(key2, value2).expect("insert");

        let value = tree.get(key1).expect("get").expect("get_some");
        assert_eq!(value1, value.as_slice());
        let value = tree.get(key2).expect("get").expect("get_some");
        assert_eq!(value2, value.as_slice());

        tree.remove(key1).expect("remove");
        assert_eq!(None, tree.get(key1).expect("get"));

        tree.remove(key2).expect("remove");
        assert_eq!(None, tree.get(key2).expect("get"));
    }

    test_empty_key(&mut tree);
    test_zeroth_discriminator_bit(&mut tree);

    // First insert keys 0..n and remove them in order n..0.
    let mut roots: Vec<Hash> = Vec::new();
    let (keys, values) = generate_long_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        test_empty_key(&mut tree);
        test_zeroth_discriminator_bit(&mut tree);

        let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
        roots.push(hash);
    }

    for i in 0..keys.len() {
        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    for i in (1..keys.len()).rev() {
        tree.remove(keys[i].as_slice()).expect("remove");

        assert_eq!(None, tree.get(keys[i].as_slice()).expect("get"));

        test_empty_key(&mut tree);
        test_zeroth_discriminator_bit(&mut tree);

        let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
        assert_eq!(hash, roots[i - 1]);
    }

    tree.remove(keys[0].as_slice()).expect("remove");

    test_empty_key(&mut tree);
    test_zeroth_discriminator_bit(&mut tree);

    let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());
}

#[test]
fn test_insert_commit_batch() {
    let mut tree = Tree::builder()
        .with_root_type(RootType::State)
        .build(Box::new(NoopReadSyncer));

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);
}

#[test]
fn test_insert_commit_each() {
    let mut tree = Tree::builder()
        .with_capacity(0, 0)
        .with_root_type(RootType::State)
        .build(Box::new(NoopReadSyncer));

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());

        Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    }

    let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);
}

#[test]
fn test_remove() {
    let mut tree = Tree::builder()
        .with_capacity(0, 0)
        .with_root_type(RootType::State)
        .build(Box::new(NoopReadSyncer));

    // First insert keys 0..n and remove them in order n..0.
    let mut roots: Vec<Hash> = Vec::new();
    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), false);
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), true);
        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());

        let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
        roots.push(hash);
    }

    assert_eq!(format!("{:?}", roots[roots.len() - 1]), ALL_ITEMS_ROOT);

    for i in (1..keys.len()).rev() {
        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), true);
        tree.remove(keys[i].as_slice()).expect("remove");

        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), false);
        assert_eq!(None, tree.get(keys[i].as_slice()).expect("get"));

        let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
        assert_eq!(hash, roots[i - 1]);
    }

    tree.remove(keys[0].as_slice()).expect("remove");
    let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());

    // Now re-insert keys n..0, remove them in order 0..n.
    for i in (0..keys.len()).rev() {
        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), false);
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), true);
        let value = tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());

        let _ = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    }

    for i in 0..keys.len() {
        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), true);
        tree.remove(keys[i].as_slice()).expect("remove");

        assert_eq!(tree.cache_contains_key(keys[i].as_slice()), false);
        assert_eq!(None, tree.get(keys[i].as_slice()).expect("get"));

        let _ = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    }

    let hash = Tree::commit(&mut tree, Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());
}

#[test]
fn test_syncer_basic() {
    let server = ProtocolServer::new(None);

    let mut tree = OverlayTree::new(
        Tree::builder()
            .with_capacity(0, 0)
            .with_root_type(RootType::State)
            .build(Box::new(NoopReadSyncer)),
    );

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }

    let (write_log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
    assert_eq!(format!("{:?}", hash), ALL_ITEMS_ROOT);

    server.apply(&write_log, hash, Default::default(), 0);

    // Create a "remote" tree that talks to the original tree via the
    // syncer interface.

    let stats = StatsCollector::new(server.read_sync());
    let remote_tree = Tree::builder()
        .with_capacity(0, 0)
        .with_root(Root {
            root_type: RootType::State,
            hash,
            ..Default::default()
        })
        .build(Box::new(stats));

    for i in 0..keys.len() {
        let value = remote_tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    let cache = remote_tree.cache.borrow();
    let stats = cache
        .get_read_syncer()
        .as_any()
        .downcast_ref::<StatsCollector>()
        .expect("stats");
    assert_eq!(keys.len(), stats.sync_get_count, "sync_get count");
    assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes count");
    assert_eq!(0, stats.sync_iterate_count, "sync_iterate count");
}

#[test]
fn test_syncer_remove() {
    let server = ProtocolServer::new(None);

    let mut tree = OverlayTree::new(
        Tree::builder()
            .with_capacity(0, 0)
            .with_root_type(RootType::State)
            .build(Box::new(NoopReadSyncer)),
    );
    let mut roots: Vec<Hash> = Vec::new();

    let mut write_log = WriteLog::new();
    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");

        let (mut wl, hash) = tree.commit_both(Default::default(), 0).expect("commit");
        roots.push(hash);
        write_log.append(&mut wl);
    }

    assert_eq!(format!("{:?}", roots[roots.len() - 1]), ALL_ITEMS_ROOT);
    server.apply(&write_log, roots[roots.len() - 1], Default::default(), 0);

    let stats = StatsCollector::new(server.read_sync());
    let mut remote_tree = Tree::builder()
        .with_capacity(0, 0)
        .with_root(Root {
            root_type: RootType::State,
            hash: roots[roots.len() - 1],
            ..Default::default()
        })
        .build(Box::new(stats));

    for i in (0..keys.len()).rev() {
        remote_tree.remove(keys[i].as_slice()).expect("remove");
    }

    let hash = Tree::commit(&mut remote_tree, Default::default(), 0).expect("commit");
    assert_eq!(hash, Hash::empty_hash());

    let cache = remote_tree.cache.borrow();
    let stats = cache
        .get_read_syncer()
        .as_any()
        .downcast_ref::<StatsCollector>()
        .expect("stats");
    assert_eq!(850, stats.sync_get_count, "sync_get count");
    assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes count");
    assert_eq!(0, stats.sync_iterate_count, "sync_iterate count");
}

#[test]
fn test_syncer_insert() {
    let server = ProtocolServer::new(None);

    let mut tree = OverlayTree::new(
        Tree::builder()
            .with_capacity(0, 0)
            .with_root_type(RootType::State)
            .build(Box::new(NoopReadSyncer)),
    );

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }

    let (write_log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
    server.apply(&write_log, hash, Default::default(), 0);

    let stats = StatsCollector::new(server.read_sync());
    let mut remote_tree = Tree::builder()
        .with_capacity(0, 0)
        .with_root(Root {
            root_type: RootType::State,
            hash,
            ..Default::default()
        })
        .build(Box::new(stats));

    for i in 0..keys.len() {
        remote_tree
            .insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }

    let cache = remote_tree.cache.borrow();
    let stats = cache
        .get_read_syncer()
        .as_any()
        .downcast_ref::<StatsCollector>()
        .expect("stats");
    assert_eq!(1000, stats.sync_get_count, "sync_get count");
    assert_eq!(0, stats.sync_get_prefixes_count, "sync_get_prefixes count");
    assert_eq!(0, stats.sync_iterate_count, "sync_iterate count");
}

#[test]
fn test_syncer_writelog_remove() {
    let server = ProtocolServer::new(None);

    let mut tree = OverlayTree::new(
        Tree::builder()
            .with_capacity(0, 0)
            .with_root_type(RootType::State)
            .build(Box::new(NoopReadSyncer)),
    );

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }

    let (write_log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
    server.apply(&write_log, hash, Default::default(), 0);

    tree.remove(keys[0].as_slice()).expect("remove");

    let previous_hash = hash;
    let (write_log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
    // Submit the write log to the protocol server. This will fail in case the server interprets the
    // write log differently.
    server.apply_existing(&write_log, previous_hash, hash, Default::default(), 0);
}

#[test]
fn test_syncer_prefetch_prefixes() {
    let server = ProtocolServer::new(None);

    let mut tree = OverlayTree::new(
        Tree::builder()
            .with_capacity(0, 0)
            .with_root_type(RootType::State)
            .build(Box::new(NoopReadSyncer)),
    );

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }

    let (write_log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
    server.apply(&write_log, hash, Default::default(), 0);

    let stats = StatsCollector::new(server.read_sync());
    let remote_tree = Tree::builder()
        .with_capacity(0, 0)
        .with_root(Root {
            root_type: RootType::State,
            hash,
            ..Default::default()
        })
        .build(Box::new(stats));

    // Prefetch keys starting with prefix "key".
    remote_tree
        .prefetch_prefixes(&vec![b"key".to_vec().into()], 1000)
        .expect("prefetch_prefixes");

    for i in 0..keys.len() {
        let value = remote_tree
            .get(keys[i].as_slice())
            .expect("get")
            .expect("get_some");
        assert_eq!(values[i], value.as_slice());
    }

    let cache = remote_tree.cache.borrow();
    let stats = cache
        .get_read_syncer()
        .as_any()
        .downcast_ref::<StatsCollector>()
        .expect("stats");
    assert_eq!(0, stats.sync_get_count, "sync_get count");
    assert_eq!(1, stats.sync_get_prefixes_count, "sync_get_prefixes count");
    assert_eq!(0, stats.sync_iterate_count, "sync_iterate count");
}

#[test]
fn test_value_eviction() {
    let mut tree = Tree::builder()
        .with_capacity(0, 512)
        .with_root_type(RootType::State)
        .build(Box::new(NoopReadSyncer));

    let (keys, values) = generate_key_value_pairs();
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }
    Tree::commit(&mut tree, Default::default(), 0).expect("commit");

    assert_eq!(
        999,
        tree.cache.borrow().stats().internal_node_count,
        "cache.internal_node_count"
    );
    // Only a subset of the leaf values should remain in cache.
    assert_eq!(
        512,
        tree.cache.borrow().stats().leaf_value_size,
        "cache.leaf_value_size"
    );
}

#[test]
fn test_node_eviction() {
    let mut tree = Tree::builder()
        .with_capacity(128, 0)
        .with_root_type(RootType::State)
        .build(Box::new(NoopReadSyncer));

    let (keys, values) = generate_key_value_pairs_ex("foo".to_string(), 150);
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }
    Tree::commit(&mut tree, Default::default(), 0).expect("commit");

    let (keys, values) = generate_key_value_pairs_ex("foo key 1".to_string(), 150);
    for i in 0..keys.len() {
        tree.insert(keys[i].as_slice(), values[i].as_slice())
            .expect("insert");
    }
    Tree::commit(&mut tree, Default::default(), 0).expect("commit");

    // Only a subset of nodes should remain in cache.
    assert_eq!(
        128,
        tree.cache.borrow().stats().internal_node_count,
        "cache.internal_node_count"
    );
    assert_eq!(
        124,
        tree.cache.borrow().stats().leaf_value_size,
        "cache.leaf_value_size"
    );
}

/// Location of the test vectors directory (from Go).
const TEST_VECTORS_DIR: &str = "../go/storage/mkvs/testdata";

fn test_special_case_from_json(fixture: &'static str) {
    let server = ProtocolServer::new(None);

    let file =
        File::open(Path::new(TEST_VECTORS_DIR).join(fixture)).expect("failed to open fixture");
    let reader = BufReader::new(file);

    let ops: tests::TestVector = serde_json::from_reader(reader).expect("failed to parse fixture");

    let mut tree = Tree::builder()
        .with_capacity(0, 0)
        .with_root_type(RootType::State)
        .build(Box::new(NoopReadSyncer));
    let mut overlay = OverlayTree::new(&mut tree);
    let mut remote_tree: Option<Tree> = None;
    let mut root = Hash::empty_hash();

    let mut commit_remote = |tree: &mut OverlayTree<_>, remote_tree: &mut Option<Tree>| {
        let (write_log, hash) = tree.commit_both(Default::default(), 0).expect("commit");
        server.apply_existing(&write_log, root, hash, Default::default(), 0);

        remote_tree.replace(
            Tree::builder()
                .with_capacity(0, 0)
                .with_root(Root {
                    root_type: RootType::State,
                    hash,
                    ..Default::default()
                })
                .build(server.read_sync()),
        );
        root = hash;
    };

    for op in ops {
        match op.op {
            tests::OpKind::Insert => {
                let key = op.key.unwrap();
                let value = op.value.unwrap_or_default();

                if let Some(ref mut remote_tree) = remote_tree {
                    remote_tree.insert(&key, &value).expect("insert");
                }

                overlay.insert(&key, &value).expect("insert");

                commit_remote(&mut overlay, &mut remote_tree);
            }
            tests::OpKind::Remove => {
                let key = op.key.unwrap();

                if let Some(ref mut remote_tree) = remote_tree {
                    // If we want a mutable remote synced tree, we must use an overlay.
                    let mut overlay = OverlayTree::new(remote_tree);

                    overlay.remove(&key).expect("remove");
                    let value = overlay.get(&key).expect("get (after remove)");
                    assert!(value.is_none(), "get (after remove) should return None");
                }

                overlay.remove(&key).expect("remove");
                let value = overlay.get(&key).expect("get (after remove)");
                assert!(value.is_none(), "get (after remove) should return None");

                commit_remote(&mut overlay, &mut remote_tree);
            }
            tests::OpKind::Get => {
                let value = overlay.get(&op.key.unwrap()).expect("get");
                assert_eq!(value, op.value, "get should return the correct value");
            }
            tests::OpKind::IteratorSeek => {
                let key = op.key.unwrap();
                let expected_key = op.expected_key.as_ref();
                let value = op.value.as_ref();

                if let Some(ref mut remote_tree) = remote_tree {
                    let mut it = remote_tree.iter();
                    it.seek(&key);
                    assert!(it.error().is_none(), "seek");

                    let item = iter::Iterator::next(&mut it);
                    assert_eq!(
                        expected_key,
                        item.as_ref().map(|p| &p.0),
                        "iterator should be at correct key"
                    );
                    assert_eq!(
                        value,
                        item.as_ref().map(|p| &p.1),
                        "iterator should be at correct value"
                    );
                }

                let mut it = overlay.iter();
                it.seek(&key);
                assert!(it.error().is_none(), "seek");

                let item = iter::Iterator::next(&mut it);
                assert_eq!(
                    expected_key,
                    item.as_ref().map(|p| &p.0),
                    "iterator should be at correct key"
                );
                assert_eq!(
                    value,
                    item.as_ref().map(|p| &p.1),
                    "iterator should be at correct value"
                );
            }
        }
    }
}

#[test]
fn test_special_case_1() {
    test_special_case_from_json("case-1.json")
}

#[test]
fn test_special_case_2() {
    test_special_case_from_json("case-2.json")
}

#[test]
fn test_special_case_3() {
    test_special_case_from_json("case-3.json")
}

#[test]
fn test_special_case_4() {
    test_special_case_from_json("case-4.json")
}

#[test]
fn test_special_case_5() {
    test_special_case_from_json("case-5.json")
}
