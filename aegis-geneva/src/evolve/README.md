# aegis-geneva/src/evolve

Bounded random generation, mutation, crossover, model fitness and generational search.

## Contract

ga.rs uses elitism and tournament selection with a caller-supplied RNG. Mutation preserves depth/parseability constraints. fitness.rs penalizes broken delivery more heavily than censor detection; search must not converge on drop and label outage as evasion. Model success does not certify live behavior.

## Key files

- [mod.rs](mod.rs)
- [ga.rs](ga.rs)
- [fitness.rs](fitness.rs)
- [random.rs](random.rs)
- [mutate.rs](mutate.rs)
- [crossover.rs](crossover.rs)

## Development and checks

Run from the repository root:

```sh
cargo test --locked -p aegis-geneva --lib evolve
```

The filter names the enclosing module; feature and OS gates can exclude its tests. Confirm the expected tests are present on the supported target.

For dependency features and launch procedures, see [aegis-geneva](../../README.md).

[Repository overview](../../../README.md) · [Parent directory](../README.md)
