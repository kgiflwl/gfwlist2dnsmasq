#!/usr/bin/env bash
set -uo pipefail

# convert gfwlist.txt -> dnsmasq conf (server/ipset)
# Usage: convert_to_dnsmasq.sh [-i input] [-o output] [-s dns_server] [-n ipset_name] [-m mode]
# mode: both (default) | server | ipset

DEFAULT_INPUT="list.txt"
INPUT="$DEFAULT_INPUT"
OUTPUT="dnsmasq_gfwlist.conf"
DNS_SERVER="127.0.0.1"
DNS_PORT="53"
IPSET_NAME="gfwlist"
MODE="both"
AUTHOR="kgiflwl"
DOWNLOAD_URL="https://raw.githubusercontent.com/gfwlist/gfwlist/master/list.txt"

usage(){
  cat <<EOF
Usage: $0 [-i input] [-o output] [-s dns_server] [-n ipset_name] [-m mode]
  -i input file (default: list.txt; auto-downloaded from $DOWNLOAD_URL when omitted)
  -o output file (default: dnsmasq_gfwlist.conf)
  -s dns server (default: 127.0.0.1)
  -w author (default: kgiflwl)
  -p dns port (default: 53)
  -n ipset name (default: gfwlist)
  -m mode: both|server|ipset (default: both)
EOF
}

while getopts ":i:o:s:p:n:m:w:h" opt; do
  case "$opt" in
    i) INPUT="$OPTARG" ;;
    o) OUTPUT="$OPTARG" ;;
    s) DNS_SERVER="$OPTARG" ;;
    p) DNS_PORT="$OPTARG" ;;
    n) IPSET_NAME="$OPTARG" ;;
    w) AUTHOR="$OPTARG" ;;
    m) MODE="$OPTARG" ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done


# If user left the input as the default, attempt to download the upstream list first
if [[ "$INPUT" == "$DEFAULT_INPUT" ]]; then
  echo "Fetching upstream gfwlist -> $INPUT" >&2
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$INPUT" 2>/dev/null || true
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$INPUT" "$DOWNLOAD_URL" 2>/dev/null || true
  fi
fi

if [[ ! -f "$INPUT" ]]; then
  echo "Input file not found: $INPUT" >&2
  exit 2
fi

tmpfile=$(mktemp)
rawtmp=$(mktemp)
trap 'rm -f "$tmpfile" "$rawtmp"' EXIT

# If the input is base64-encoded (common for some gfwlist exports), try to decode it.
if base64 -d "$INPUT" > "$rawtmp" 2>/dev/null; then
  # if decoded looks textual (contains alphabetic or dot chars) use decoded
  if grep -q '[A-Za-z\.]' "$rawtmp"; then
    : # keep decoded in $rawtmp
  else
    cp "$INPUT" "$rawtmp"
  fi
else
  cp "$INPUT" "$rawtmp"
fi

# Split on pipe as many lists contain '|' concatenated entries, then process line-by-line
tr '|' '\n' < "$rawtmp" > "$tmpfile" || true

# Two-pass awk: First pass identifies whitelisted domains; second pass generates output
# This ensures whitelist rules take precedence (no ipset if the domain is whitelisted anywhere)
whitelist_file=$(mktemp)
awk -f - <<'PASS1' "$rawtmp" > "$whitelist_file" || true
function trim(s){ gsub(/^\s+|\s+$/,"",s); return s }
function extract_domain(line,    domain){
  sub(/^[a-z0-9._%+-]+:\/\//, "", line);
  sub(/^www\./, "", line);
  sub(/\/.*$/, "", line);
  sub(/^[\.\|\^\*]+/, "", line);
  sub(/[^a-z0-9.\-].*$/, "", line);
  domain=tolower(line);
  sub(/:.*$/, "", domain);
  if(domain=="") return "";
  if(domain ~ /[@/:=,?\[\]\(\)]/) return "";
  if(domain ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return "";
  if(index(domain, ".")==0) return "";
  gsub(/[^a-z0-9.\-]/, "", domain);
  return (domain=="") ? "" : domain;
}
BEGIN{ IGNORECASE=1 }
{
  line=trim($0);
  if(line=="") next;
  if(line !~ /^@@/) next;
  sub(/^@@/, "", line);
  if(line ~ /^!/ || line ~ /^\[/) next;
  # Handle ||domain, |/path, /regex patterns - extract domain only
  sub(/^[\|\^\/]/, "", line);
  domain=extract_domain(line);
  if(domain!="") {
    if(!seen[domain]++) print domain;
  }
}
PASS1

# Second pass: main processing with whitelist exclusions
awk -v DNS_SERVER="$DNS_SERVER" -v DNS_PORT="$DNS_PORT" -v IPSET_NAME="$IPSET_NAME" -v MODE="$MODE" -f - <<'PASS2' "$tmpfile" "$whitelist_file" > "$OUTPUT" || true
function trim(s){ gsub(/^\s+|\s+$/,"",s); return s }
BEGIN{ 
  IGNORECASE=1
  while((getline < ARGV[2]) > 0) whitelist_only[$0]=1;
  close(ARGV[2]);
  ARGV[2]="";
}
{
  line=trim($0);
  if(line=="") next;
  if(line ~ /^!/ || line ~ /^\[/ || line ~ /^@@/) next;
  sub(/^[a-z0-9._%+-]+:\/\//, "", line);
  sub(/^www\./, "", line);
  sub(/\/.*$/, "", line);
  sub(/^[\.\|\^\*]+/, "", line);
  sub(/[^a-z0-9.\-].*$/, "", line);
  domain=tolower(line);
  sub(/:.*$/, "", domain);
  if(domain=="") next;
  if(domain ~ /[@/:=,?\[\]\(\)]/) next;
  if(domain ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next;
  if(index(domain, ".")==0) next;
  gsub(/[^a-z0-9.\-]/, "", domain);
  if(domain=="") next;
  if(!seen[domain]++){
    # Skip whitelisted domains entirely (no server, no ipset)
    if(!whitelist_only[domain]){
      if(MODE=="both" || MODE=="server"){
        if(DNS_PORT!="" && DNS_PORT!="53")
          print "server=/"domain"/"DNS_SERVER"#"DNS_PORT;
        else
          print "server=/"domain"/"DNS_SERVER;
      }
      if(MODE=="both" || MODE=="ipset"){
        print "ipset=/"domain"/"IPSET_NAME;
      }
    }
  }
}
PASS2

rm -f "$whitelist_file"

# Sort output by domain name, keeping server and ipset pairs together
sorted_tmp=$(mktemp)
awk -F'[=/]' '{ print $3, NR, $0 }' "$OUTPUT" | sort -k1,1 -k2,2n | cut -d' ' -f3- > "$sorted_tmp" && mv "$sorted_tmp" "$OUTPUT" || true

# Count server+ipset pairs (an entry is a domain that has both server and ipset lines)
entry_count=$(awk -F'[=/]' '
  /^server=/{ s[$3]=1 }
  /^ipset=/{ i[$3]=1 }
  END{ c=0; for(d in s) if(i[d]) c++; print c }
' "$OUTPUT")

# Prepend header comments with timestamp, creator and entry count
timestamp=$(LC_ALL=C date -u +"%a, %d %b %Y %H:%M:%S %z")
hdr_tmp=$(mktemp)
cat > "$hdr_tmp" <<EOF
# Generated by gfwlist2dnsmasq.sh
# Created: $timestamp
# Author: $AUTHOR
# Entries (server+ipset pairs): $entry_count

EOF
cat "$hdr_tmp" "$OUTPUT" > "$OUTPUT".tmp && mv "$OUTPUT".tmp "$OUTPUT" && rm -f "$hdr_tmp"

lines=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
echo "Wrote $lines lines to $OUTPUT (entries: $entry_count, author: $AUTHOR)"
