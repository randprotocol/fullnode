# Sourced by the chain-cut scripts (audit v3, OPS-1): a validator's secret key file must not
# live inside this repository. deploy/node-a..f.key.json were committed and the repository is
# public, so every chain from 8 to 13 ran on seeds anyone could read. The next cut takes fresh
# keys from a directory outside the tree (KEYS_DIR) and this refuses anything else.
#
#   refuse_in_tree_key <path>   exits 1 when <path> resolves inside the repository
refuse_in_tree_key() {
  local path=$1 root abs
  root=$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)
  root=$(cd "$root" && pwd -P)
  if [ ! -f "$path" ]; then
    echo "key-guard: $path does not exist" >&2
    exit 1
  fi
  abs=$(cd "$(dirname "$path")" && pwd -P)/$(basename "$path")
  case "$abs" in
    "$root"/*)
      echo "key-guard: refusing $path — a validator key inside the repository ($root) is a key" >&2
      echo "key-guard: anyone with the repository holds; keep keys under KEYS_DIR outside the tree" >&2
      exit 1
      ;;
  esac
}
