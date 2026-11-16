# Nexthop Fanout Hash Benchmark

This is a small synthetic benchmark for the `match nexthop-fanout` hash shape.

By default, it simulates one matcher evaluation as four FRR `jhash()` calls:

```text
jhash(peer_ip)
jhash(vtep_ip, key)
jhash(prefix metadata, key)
jhash(masked prefix bytes, key)
key % 36 < 20
```

Build:

```sh
make -C nexthop_fanout_hash_bench
```

Quick run:

```sh
./nexthop_fanout_hash_bench/fanout_hash_bench 100000000
```

Use the embedded XXH32-style hash instead of FRR `jhash()`:

```sh
./nexthop_fanout_hash_bench/fanout_hash_bench -f 100000000
```

Use FNV-1 instead of FRR `jhash()`:

```sh
./nexthop_fanout_hash_bench/fanout_hash_bench -1 100000000
```

Full worst-case run, using the default 18B evaluations:

```sh
./nexthop_fanout_hash_bench/fanout_hash_bench
```

The full run can take minutes or longer. This measures only the hash/modulo part, not FRR route-map walking, BGP update generation, attribute handling, or update-group behavior.
