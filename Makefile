.PHONY: test build image recover reveal e2e deps
test: ; cargo test --release
build: ; cargo build --release
image: ; ./blocktools build
# One command for T: put the phrase in in/seed.txt
recover: ; ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --count 5'
reveal: ; ./blocktools reveal 'seed-repair < /in/seed.txt | seed-to-master | derive --count 5'
e2e: build ; sh scripts/e2e-local.sh
deps: ; sh scripts/check-deps.sh
