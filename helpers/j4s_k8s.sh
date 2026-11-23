#!/usr/bin/env bash
# j4s_k8s.sh - Kubernetes investigation helpers for CVE-2026-114938 (Java4Shell).
# Self-contained (bash 3.2+, kubectl, python3 stdlib for JSON). Read-only unless you use j4s_flag.sh k8s-apply.
#
#   helpers/j4s_k8s.sh pods   [-n ns | -A] [-l selector]   # JVM-like containers: image, JVM env, flag status
#   helpers/j4s_k8s.sh images [-n ns | -A]                 # distinct JVM-like images with version classification
#   helpers/j4s_k8s.sh missing [-n ns | -A]                # workloads (Deployment/StatefulSet/DaemonSet) lacking the flag
#   helpers/j4s_k8s.sh nodes                               # nodes: arch + CPU model (VBMI needs per-node check)
#   add --json to pods|images|missing for machine-readable output
set -u

j4s_k8s__ns_args() {
  local -a out=(-A)
  while [[ $# -gt 0 ]]; do
    case "$1" in -n) out=(-n "$2"); shift 2 ;; -A) out=(-A); shift ;; *) shift ;; esac
  done
  printf '%s\n' "${out[@]}"
}

j4s_k8s__py() {
  python3 -I -c '
import json, re, sys
mode = sys.argv[1]; want_json = sys.argv[2] == "1"
data = json.load(sys.stdin)
flag_re = re.compile(r"(?:^|[\s\"=])(-XX:-UseBASE64Intrinsics|-XX:UseAVX=[0-2])(?:[\s\"]|$)")
enable_re = re.compile(r"-XX:\+UseBASE64Intrinsics")
jvm_re = re.compile(r"(java|jdk|jre|jvm|openjdk|temurin|corretto|zulu|liberica|sapmachine|graalvm|spring|tomcat|kafka|elasticsearch|opensearch|keycloak|jenkins|solr|cassandra|zookeeper|flink|nifi|sonarqube|artifactory|nexus)", re.I)
ver_re = re.compile(r"(?<![\d.])(\d+(?:\.\d+){1,4})(?:_\d+)?(?![\d.])")
BASE = {17:(17,0,21,0,3),21:(21,0,13,1),25:(25,0,5,1),27:(27,0,1,1)}; EOL={18,19,20,22,23,24,26}
def classify(tag):
    m = ver_re.search(tag or "")
    if not m: return "UNKNOWN_VERSION"
    t = tuple(int(x) for x in m.group(1).split("."))
    mj = t[0]
    if mj <= 16: return "UNAFFECTED(<=16)"
    if mj in EOL: return "VULN_RANGE(EOL)"
    if mj in BASE:
        b = BASE[mj]; p = tuple(list(t)+[0]*5)[:len(b)]
        if mj == 17 and p[1]==0 and p[2] < 6: return "UNAFFECTED(<17.0.6)"
        return "PATCHED" if p >= b else "VULN_RANGE"
    return "VULN_RANGE(verify)"
rows = []
items = data.get("items", [])
for obj in items:
    kind = obj.get("kind","Pod"); meta = obj.get("metadata", {})
    spec = obj.get("spec", {})
    tmpl = spec.get("template", {}).get("spec", spec)  # workloads vs pods
    statuses = {s.get("name"): s for s in obj.get("status", {}).get("containerStatuses", [])}
    for c in tmpl.get("containers", []) + tmpl.get("initContainers", []):
        image = c.get("image", "")
        args = " ".join(c.get("args", []) + c.get("command", []))
        env = {e.get("name"): e.get("value","<valueFrom>") for e in c.get("env", []) if e.get("name") in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","JAVA_OPTS","CATALINA_OPTS")}
        envstr = " ".join(f"{k}={v}" for k,v in env.items())
        combined = f"{args} {envstr}"
        jvm_like = bool(jvm_re.search(f"{image} {combined}")) or bool(env)
        if not jvm_like: continue
        rows.append({"kind": kind, "namespace": meta.get("namespace","default"), "name": meta.get("name"), "container": c.get("name"),
                     "image": image, "imageID": statuses.get(c.get("name"), {}).get("imageID",""),
                     "version_status": classify(image.rsplit(":",1)[-1] if ":" in image else ""),
                     "jvm_env": envstr, "args": args[:120],
                     "flag": "EXPLICITLY_ENABLED" if enable_re.search(combined) else "PRESENT" if flag_re.search(" "+combined+" ") else "MISSING"})
if mode == "images":
    agg = {}
    for r in rows:
        a = agg.setdefault(r["image"], {"image": r["image"], "version_status": r["version_status"], "containers": 0, "flag_missing": 0, "namespaces": set()})
        a["containers"] += 1; a["flag_missing"] += r["flag"] != "PRESENT"; a["namespaces"].add(r["namespace"])
    rows = [{**v, "namespaces": sorted(v["namespaces"])} for v in agg.values()]
    rows.sort(key=lambda r: (not r["version_status"].startswith("VULN"), -r["flag_missing"]))
elif mode == "missing":
    rows = [r for r in rows if r["flag"] != "PRESENT"]
if want_json:
    print(json.dumps(rows, indent=2)); sys.exit(2 if any(r.get("flag","MISSING") != "PRESENT" for r in rows) else 0)
if mode == "images":
    print("{:60} {:20} {:>4} {:>6} namespaces".format("image", "status", "ctrs", "noflag"))
    for r in rows: print("{:60} {:20} {:>4} {:>6} {}".format(r["image"][:60], r["version_status"], r["containers"], r["flag_missing"], ",".join(r["namespaces"])))
else:
    print("{:12} {:20} {:40} {:18} {:18} {:20} image".format("kind", "namespace", "name", "container", "flag", "version"))
    for r in rows: print("{:12} {:20} {:40} {:18} {:18} {:20} {}".format(r["kind"], r["namespace"], r["name"][:40], r["container"][:18], r["flag"], r["version_status"], r["image"]))
    print("-- {} JVM-like container(s); flag missing/enabled: {}".format(len(rows), sum(1 for r in rows if r["flag"] != "PRESENT")), file=sys.stderr)
sys.exit(2 if any(r.get("flag", "MISSING") != "PRESENT" or r.get("flag_missing", 0) for r in rows) else 0)
' "$@"
}

j4s_k8s_pods() {
  local -a ns; mapfile -t ns < <(j4s_k8s__ns_args "$@") 2>/dev/null || ns=($(j4s_k8s__ns_args "$@"))
  local sel=() json=0
  while [[ $# -gt 0 ]]; do case "$1" in -l) sel=(-l "$2"); shift 2 ;; --json) json=1; shift ;; *) shift ;; esac; done
  kubectl get pods "${ns[@]}" "${sel[@]}" -o json | j4s_k8s__py pods "$json"
}

j4s_k8s_images() {
  local -a ns; ns=($(j4s_k8s__ns_args "$@")); local json=0; [[ " $* " == *" --json "* ]] && json=1
  kubectl get pods "${ns[@]}" -o json | j4s_k8s__py images "$json"
}

j4s_k8s_missing() {
  local -a ns; ns=($(j4s_k8s__ns_args "$@")); local json=0; [[ " $* " == *" --json "* ]] && json=1
  kubectl get deployments,statefulsets,daemonsets "${ns[@]}" -o json | j4s_k8s__py missing "$json"
}

j4s_k8s_nodes() {
  echo "Note: Kubernetes does not expose avx512_vbmi; use node labels from NFD (feature.node.kubernetes.io/cpu-cpuid.AVX512VBMI) if installed,"
  echo "      otherwise run helpers/j4s_proc.sh cpu on each node (or a privileged DaemonSet)."
  kubectl get nodes -o custom-columns='NODE:.metadata.name,ARCH:.status.nodeInfo.architecture,OS:.status.nodeInfo.osImage,KERNEL:.status.nodeInfo.kernelVersion,VBMI_LABEL:.metadata.labels.feature\.node\.kubernetes\.io/cpu-cpuid\.AVX512VBMI'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  command -v kubectl >/dev/null 2>&1 || { echo "kubectl not found in PATH" >&2; exit 1; }
  cmd="${1:-}"; shift || true
  case "$cmd" in
    pods) j4s_k8s_pods "$@" ;;
    images) j4s_k8s_images "$@" ;;
    missing) j4s_k8s_missing "$@" ;;
    nodes) j4s_k8s_nodes ;;
    *) sed -n '2,9p' "$0"; exit 2 ;;
  esac
fi
