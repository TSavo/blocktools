# image-size.sh refuses an image whose revision label is not HEAD (stale image), with a stub docker;
# no daemon needed. A label equal to HEAD gets past the check to the measurement.
set -eu
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cat > $T/docker <<'S'
#!/bin/sh
case "$*" in
  *Labels*) cat "$STUB_LABEL";;
  *"{{.Size}}"*) echo 123;;
  info*) echo stub;;
  save*) exit 1;;
esac
S
chmod +x $T/docker
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then echo "skip image-size stale-image test: tracked tree dirty"; else
  echo 0000000000000000000000000000000000000000 > $T/label
  out=$(STUB_LABEL=$T/label BLOCKTOOLS_DOCKER=$T/docker sh scripts/image-size.sh 2>&1) && { echo "FAIL image-size accepted a stale image"; exit 1; }
  echo "$out" | grep -q "FAIL image-size: image blocktools:local was built from '0000" || { echo "FAIL image-size stale: $out"; exit 1; }
  echo "ok   image-size refuses an image built from another commit"
  git rev-parse HEAD > $T/label
  out=$(STUB_LABEL=$T/label BLOCKTOOLS_DOCKER=$T/docker sh scripts/image-size.sh 2>&1) || true  # allow-true: the stub cannot docker save; only the commit check is under test
  echo "$out" | grep -q "built from" && { echo "FAIL image-size refused an image labelled HEAD: $out"; exit 1; }
  echo "ok   image-size accepts an image labelled with HEAD"
fi
