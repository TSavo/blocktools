.PHONY: test build image recover reveal e2e
test: ; cargo test --release
build: ; cargo build --release
image: ; ./keyrescue build
# One command for T: put the phrase in in/seed.txt
recover: ; ./keyrescue run 'seed-repair --in /in/seed.txt | derive --count 5'
reveal: ; ./keyrescue reveal 'seed-repair --in /in/seed.txt | derive --count 5'
e2e: build ; sh scripts/e2e-local.sh
