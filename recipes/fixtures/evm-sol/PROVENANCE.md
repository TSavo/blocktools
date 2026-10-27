# evm-sol fixtures

Built off-repo (blocktools runs no compiler) with solc-js 0.8.26+commit.8a97fa7a (npm `solc@0.8.26`) from
`src/Counter.sol` and `src/Lib.sol` here, standard JSON input with optimizer enabled, runs 200, output selection
`metadata`, `evm.bytecode.object`, `evm.deployedBytecode.object`. Files:

- `Counter.metadata.json`: the `metadata` string exactly as solc returned it (no trailing newline added).
- `Counter.runtime.hex`: `0x` + `evm.deployedBytecode.object`, newline.
- `Counter.creation.hex`: `0x` + `evm.bytecode.object`, newline.

Used by `tools/bytecode-inspect/tests/metadata.rs` and `recipes/evm-contract-data.md`.
