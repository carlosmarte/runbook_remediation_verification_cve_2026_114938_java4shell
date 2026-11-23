#!/usr/bin/env bash
# Regenerate the worked examples from the synthetic evidence in examples/data/.
#   report-template/examples/build-examples.sh
set -eu
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
DATA="$HERE/data"

python3 -I "$ROOT/tools/j4s_facts.py" \
  --audit "$DATA/audit-web-01.json" "$DATA/audit-batch-02.json" \
  --audit-before "$DATA/before/audit-web-01.json" \
  --gh-scan "$DATA/estate.json" \
  --actions "$DATA/posture.tsv" \
  --source "$DATA/src.json" \
  --jars "$DATA/findings.jsonl" \
  --gate "$DATA/gate.log" \
  --crashes "$DATA/crashes.json" \
  --b64 "$DATA/traffic.json" \
  --extra "$DATA/narrative.json" \
  --meta org="Acme Corp (fictional example)" --meta scope="Payments, Identity and Finance Ops production" \
  --meta report_date=2026-11-24 --meta period="2026-11-17 to 2026-11-24" \
  --meta prepared_by="Platform Security" --meta owner="CISO" --meta distribution="Security leadership, engineering directors" \
  --sla-mitigate-days 2 --sla-patch-days 30 \
  -o "$HERE/facts.example.json"

status=0
for t in "$ROOT"/templates/R*.md; do
  name="$(basename "$t" .md)"
  python3 -I "$ROOT/tools/render.py" "$t" "$HERE/facts.example.json" -o "$HERE/$name.example.md" || status=1
done
echo "examples written to $HERE" >&2
exit $status
