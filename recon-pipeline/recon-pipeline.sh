#!/usr/bin/env bash

################################################################################
# Web Reconnaissance Pipeline
# A conservative, Docker/Podman-based recon tool with intelligent scoring
#
# LEGAL NOTICE:
# This tool must ONLY be used on systems you own or have explicit written
# authorization to test. Unauthorized access to computer systems is illegal
# under laws including CFAA (US), Computer Misuse Act (UK), and similar
# legislation worldwide. The authors assume no liability for misuse.
#
# Usage: ./recon-pipeline.sh --target <IP/hostname> --output <directory>
################################################################################

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
DOCKER_CMD="docker"
THREADS_LOW=10
THREADS_MEDIUM=20
TIMEOUT=10
MEMORY_LIMIT="512m"
CPU_LIMIT="1.0"
MEMORY_HEAVY="2g"


################################################################################
# Helper Functions
################################################################################

log_info() {
    echo -e "${BLUE}[*] $1${NC}"
}

log_success() {
    echo -e "${GREEN}[+] $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

log_error() {
    echo -e "${RED}[-] $1${NC}"
}

print_banner() {
    cat << "BANNER"

╔═══════════════════════════════════════════════════════════╗
║           Web Reconnaissance Pipeline v1.0                ║
║                                                           ║
║  Conservative • Docker-based • Resource-efficient         ║
╚═══════════════════════════════════════════════════════════╝
BANNER
}

usage() {
    cat << USAGE
Usage: $0 --target <TARGET> --output <OUTPUT_DIR> [OPTIONS]

Required:
  --target <TARGET>       Target IP address or hostname
  --output <OUTPUT_DIR>   Output directory for results

Optional:
  --wordlist <FILE>       Custom wordlist (default: wordlists/common.txt)
  --deep                  Enable deep scanning (larger wordlists, more tools)
  --threads <NUM>         Number of threads (default: 10 for light, 20 for deep)
  --timeout <SECONDS>     Request timeout in seconds (default: 10)
  --skip-nmap             Skip nmap port discovery
  --skip-screenshots      Skip screenshot generation
  --help                  Show this help message

Examples:
  # Basic scan
  $0 --target 192.168.1.100 --output ./results

  # Deep scan with custom wordlist
  $0 --target example.com --output ./results --deep --wordlist custom.txt

  # Quick web-only scan (skip port discovery)
  $0 --target https://example.com --output ./results --skip-nmap

USAGE
    exit 1
}


# -------------------------
# Argument parsing
# -------------------------
parse_args() {
  # Defaults (already set above, but reaffirm here if needed)
  DEEP=false
  SKIP_NMAP=false
  SKIP_SCREENSHOTS=false

  if [[ $# -eq 0 ]]; then
    usage
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --help|-h)
        usage
        ;;
      --target)
        TARGET="$2"
        shift 2
        ;;
      --output)
        OUTPUT_DIR="$2"
        shift 2
        ;;
      --wordlist)
        WORDLIST="$2"
        shift 2
        ;;
      --deep)
        DEEP=true
        shift
        ;;
      --threads)
        THREADS_OVERRIDE="$2"
        shift 2
        ;;
      --timeout)
        TIMEOUT="$2"
        shift 2
        ;;
      --skip-nmap)
        SKIP_NMAP=true
        shift
        ;;
      --skip-screenshots)
        SKIP_SCREENSHOTS=true
        shift
        ;;
      *)
        log_error "Unknown option: $1"
        usage
        ;;
    esac
  done

  # Basic validation
  if [[ -z "${TARGET:-}" || -z "${OUTPUT_DIR:-}" ]]; then
    log_error "Missing required --target or --output"
    usage
  fi

  # Apply thread override if provided
  if [[ -n "${THREADS_OVERRIDE:-}" ]]; then
    THREADS_LOW="${THREADS_OVERRIDE}"
    THREADS_MEDIUM="${THREADS_OVERRIDE}"
  fi

  log_info "Target: ${TARGET}"
  log_info "Output: ${OUTPUT_DIR}"
  log_info "Deep mode: ${DEEP}"
}

# Call parser with script args
parse_args "$@"

check_requirements() {
    log_info "Checking requirements..."

    # Detect container runtime first
    if command -v podman &> /dev/null; then
        DOCKER_CMD="podman"
        log_info "Detected podman as container runtime"
    elif command -v docker &> /dev/null; then
        DOCKER_CMD="docker"
        log_info "Detected docker as container runtime"
    else
        log_error "Docker/Podman not found. Please install Docker or Podman."
        exit 1
    fi

    # Check if jq is available (needed for JSON parsing)
    if ! command -v jq &> /dev/null; then
        log_warning "jq not found. Installing via container when needed."
    fi

    # Check if sqlite3 is available
    if ! command -v sqlite3 &> /dev/null; then
        log_warning "sqlite3 not found. Will use container-based sqlite."
    fi

    log_success "Requirements check passed"
}


create_output_structure() {
    local output_dir=$1

    log_info "Creating output directory structure..."

    mkdir -p "${output_dir}"/{raw,enrichment,screenshots,wordlists}

    # Copy wordlist to output directory for record keeping
    if [[ -f "${WORDLIST}" ]]; then
        cp "${WORDLIST}" "${output_dir}/wordlists/used_wordlist.txt"
    fi

    log_success "Output structure created at ${output_dir}"
}

detect_waf_cdn() {
    local url=$1
    local output_dir=$2

    log_info "Detecting WAF/CDN for ${url}..."

    # Use curl to check headers
    local headers
    headers=$(${DOCKER_CMD} run --rm --network=host \
        curlimages/curl:latest \
        -s -I -L --max-time 10 \
        "${url}" 2>/dev/null || echo "")

    local waf_detected=false
    local waf_type="none"

    # Check for common WAF/CDN signatures
    if echo "${headers}" | grep -qi "cloudflare\|cf-ray"; then
        waf_detected=true
        waf_type="Cloudflare"
    elif echo "${headers}" | grep -qi "x-amz-cf-id\|cloudfront"; then
        waf_detected=true
        waf_type="AWS CloudFront"
    elif echo "${headers}" | grep -qi "akamai"; then
        waf_detected=true
        waf_type="Akamai"
    elif echo "${headers}" | grep -qi "incapsula\|x-cdn"; then
        waf_detected=true
        waf_type="Imperva Incapsula"
    elif echo "${headers}" | grep -qi "sucuri"; then
        waf_detected=true
        waf_type="Sucuri"
    fi

    if [[ "${waf_detected}" == "true" ]]; then
        log_warning "WAF/CDN detected: ${waf_type}"
        echo "${url},${waf_type}" >> "${output_dir}/waf_detected.csv"
        return 0
    else
        log_info "No WAF/CDN detected"
        return 1
    fi
}

################################################################################
# Stage 1: Port Discovery
################################################################################
run_nmap_discovery() {
    local target=$1
    local output_dir=$2

    log_info "Stage 1: Running nmap port discovery on ${target}..."

    # Use TCP connect scan (-sT) instead of SYN scan to avoid raw socket requirement
    ${DOCKER_CMD} run --rm --network=host \
        --cpus="${CPU_LIMIT}" \
        --memory="${MEMORY_LIMIT}" \
        -v "${output_dir}/raw:/output:Z" \
        instrumentisto/nmap:latest \
        -sT -T4 -Pn --top-ports 1000 \
        --open \
        -oX /output/ports.xml \
        -oN /output/ports.txt \
        "${target}" || {
            log_error "Nmap scan failed"
            return 1
        }

    # Parse open ports
    if [[ -f "${output_dir}/raw/ports.xml" ]]; then
        grep -oP 'portid="\K[0-9]+' "${output_dir}/raw/ports.xml" | sort -u > "${output_dir}/raw/open_ports.txt" || true
        grep -E '(80|443|8000|8008|8080|8443|8888|9000|9090)' "${output_dir}/raw/open_ports.txt" > "${output_dir}/raw/http_ports.txt" || true

        local port_count
        port_count=$(wc -l < "${output_dir}/raw/open_ports.txt" || echo "0")
        log_success "Found ${port_count} open ports"
        return 0
    else
        log_error "Nmap output not found"
        # Create empty files so the script doesn't fail later
        touch "${output_dir}/raw/open_ports.txt"
        touch "${output_dir}/raw/http_ports.txt"
        return 1
    fi
}

################################################################################
# Stage 2: HTTP Probing
################################################################################

run_httpx_probe() {
    local target=$1
    local output_dir=$2
    local ports_file="${output_dir}/raw/http_ports.txt"

    log_info "Stage 2: Running httpx probe on ${target}..."

    # Build target URLs
    local target_urls="${output_dir}/raw/target_urls.txt"
    > "${target_urls}"  # Clear file

    if [[ -f "${ports_file}" ]] && [[ -s "${ports_file}" ]]; then
        # Probe specific ports found by nmap
        while read -r port; do
            echo "http://${target}:${port}" >> "${target_urls}"
            if [[ "${port}" == "443" ]] || [[ "${port}" == "8443" ]]; then
                echo "https://${target}:${port}" >> "${target_urls}"
            fi
        done < "${ports_file}"
    else
        # Fallback: probe common ports
        log_warning "No port scan results, probing common HTTP ports..."
        echo "http://${target}" >> "${target_urls}"
        echo "https://${target}" >> "${target_urls}"
        echo "http://${target}:8080" >> "${target_urls}"
        echo "https://${target}:8443" >> "${target_urls}"
    fi

    # Run httpx with comprehensive probing
    ${DOCKER_CMD} run --rm --network=host \
        --cpus="${CPU_LIMIT}" --memory="${MEMORY_LIMIT}" \
        -v "${output_dir}/raw:/output:Z" \
        projectdiscovery/httpx:latest \
        -l /output/target_urls.txt \
        -json \
        -status-code \
        -title \
        -content-type \
        -server \
        -tech-detect \
        -method \
        -tls-grab \
        -timeout ${TIMEOUT} \
        -threads ${THREADS_LOW} \
        -o /output/http_probe.jsonl \
        -silent || {
            log_warning "httpx probe encountered errors (may be normal if some targets are down)"
        }

    if [[ -f "${output_dir}/raw/http_probe.jsonl" ]] && [[ -s "${output_dir}/raw/http_probe.jsonl" ]]; then
        local url_count
        url_count=$(wc -l < "${output_dir}/raw/http_probe.jsonl" || echo "0")
        log_success "Probed ${url_count} HTTP endpoints"
        return 0
    else
        log_error "No HTTP services found or httpx failed"
        return 1
    fi
}


################################################################################
# Stage 3: Scoring & Filtering
################################################################################

calculate_score() {
    local url=$1
    local status=$2
    local title=$3
    local content_type=$4
    local tech=$5
    local score=0

    # HTML content-type: +2
    if echo "${content_type}" | grep -qi "text/html"; then
        score=$((score + 2))
    fi

    # Success/redirect/auth status: +2
    if [[ "${status}" =~ ^(200|30[0-9]|401|403)$ ]]; then
        score=$((score + 2))
    fi

    # Non-empty title: +2
    if [[ -n "${title}" ]] && [[ "${title}" != "null" ]] && [[ "${title}" != "" ]]; then
        score=$((score + 2))
    fi

    # CMS detected: +3
    if echo "${tech}" | grep -qiE "wordpress|joomla|drupal|magento|prestashop"; then
        score=$((score + 3))
    fi

    # Admin/login paths: +3
    if echo "${url}" | grep -qiE "admin|login|wp-admin|dashboard|panel|cpanel"; then
        score=$((score + 3))
    fi

    # Default/error pages: -3
    if echo "${title}" | grep -qiE "404|not found|error|default|test page|welcome to|it works"; then
        score=$((score - 3))
    fi

    # Ensure score doesn't go negative
    if [[ ${score} -lt 0 ]]; then
        score=0
    fi

    echo "${score}"
}

score_and_filter() {
    local output_dir=$1
    local probe_file="${output_dir}/raw/http_probe.jsonl"
    local scored_file="${output_dir}/scored_targets.csv"

    log_info "Stage 3: Scoring and filtering targets..."

    # Create CSV header
    echo "url,score,status,title,content_type,server,technologies,priority" > "${scored_file}"

    # Process each probed URL
    while IFS= read -r line; do
        # Extract fields using grep/sed (fallback if jq not available)
        local url status title content_type server tech

        if command -v jq &> /dev/null; then
            url=$(echo "${line}" | jq -r '.url // empty')
            status=$(echo "${line}" | jq -r '.status_code // empty')
            title=$(echo "${line}" | jq -r '.title // empty' | sed 's/,/ /g')
            content_type=$(echo "${line}" | jq -r '.content_type // empty')
            server=$(echo "${line}" | jq -r '.webserver // empty')
            tech=$(echo "${line}" | jq -r '.technologies[]? // empty' | tr '\n' '|' | sed 's/|$//')
        else
            # Fallback parsing without jq
            url=$(echo "${line}" | grep -oP '"url":"\K[^"]+' || echo "")
            status=$(echo "${line}" | grep -oP '"status_code":\K[0-9]+' || echo "0")
            title=$(echo "${line}" | grep -oP '"title":"\K[^"]+' || echo "")
            content_type=$(echo "${line}" | grep -oP '"content_type":"\K[^"]+' || echo "")
            server=$(echo "${line}" | grep -oP '"webserver":"\K[^"]+' || echo "")
            tech=""
        fi

        # Skip empty URLs
        [[ -z "${url}" ]] && continue

        # Calculate score
        local score
        score=$(calculate_score "${url}" "${status}" "${title}" "${content_type}" "${tech}")

        # Determine priority
        local priority="low"
        if [[ ${score} -ge 7 ]]; then
            priority="high"
        elif [[ ${score} -ge 4 ]]; then
            priority="medium"
        fi

        # Write to CSV (escape commas in fields)
        echo "${url},${score},${status},${title},${content_type},${server},${tech},${priority}" >> "${scored_file}"

    done < "${probe_file}"

    # Generate priority lists
    awk -F',' '$8=="high" {print $1}' "${scored_file}" > "${output_dir}/high_priority.txt"
    awk -F',' '$8=="medium" || $8=="high" {print $1}' "${scored_file}" > "${output_dir}/promising.txt"

    local high_count medium_count
    high_count=$(wc -l < "${output_dir}/high_priority.txt" 2>/dev/null || echo "0")
    medium_count=$(( $(wc -l < "${output_dir}/promising.txt" 2>/dev/null || echo "0") - high_count ))

    log_success "Scoring complete: ${high_count} high-priority, ${medium_count} medium-priority targets"
}

################################################################################
# Stage 4: Enrichment (robots.txt, sitemap.xml, tech fingerprinting)
################################################################################

fetch_robots_sitemap() {
    local url=$1
    local output_dir=$2

    # Extract domain for filename
    local domain
    domain=$(echo "${url}" | sed -E 's|https?://||' | sed 's|/.*||' | sed 's|:|-|g')

    local robots_file="${output_dir}/enrichment/${domain}_robots.txt"
    local sitemap_file="${output_dir}/enrichment/${domain}_sitemap.xml"

    # Fetch robots.txt
    ${DOCKER_CMD} run --rm --network=host \
        --cpus="0.5" --memory="256m" \
        curlimages/curl:latest \
        -s -L --max-time 5 \
        "${url}/robots.txt" > "${robots_file}" 2>/dev/null || true

    # Check if robots.txt exists
    if [[ -s "${robots_file}" ]] && ! grep -q "404\|Not Found" "${robots_file}"; then
        log_info "Found robots.txt for ${url}"

        # Extract interesting paths from robots.txt
        grep -E "Disallow:|Allow:" "${robots_file}" | \
            sed -E 's/^(Disallow|Allow): ?//' | \
            grep -v '^$' > "${output_dir}/enrichment/${domain}_interesting_paths.txt" || true
    else
        rm -f "${robots_file}"
    fi

    # Fetch sitemap.xml
    ${DOCKER_CMD} run --rm --network=host \
        --cpus="0.5" --memory="256m" \
        curlimages/curl:latest \
        -s -L --max-time 5 \
        "${url}/sitemap.xml" > "${sitemap_file}" 2>/dev/null || true

    # Check if sitemap exists
    if [[ -s "${sitemap_file}" ]] && grep -q "<urlset\|<sitemap" "${sitemap_file}"; then
        log_info "Found sitemap.xml for ${url}"
    else
        rm -f "${sitemap_file}"
    fi
}

run_enrichment() {
    local output_dir=$1
    local promising_file="${output_dir}/promising.txt"

    log_info "Stage 4: Running enrichment on promising targets..."

    if [[ ! -f "${promising_file}" ]] || [[ ! -s "${promising_file}" ]]; then
        log_warning "No promising targets to enrich"
        return 0
    fi

    local count=0
    while IFS= read -r url; do
        [[ -z "${url}" ]] && continue

        log_info "Enriching ${url}..."

        # Detect WAF/CDN
        detect_waf_cdn "${url}" "${output_dir}" || true

        # Fetch robots.txt and sitemap.xml
        fetch_robots_sitemap "${url}" "${output_dir}"

        count=$((count + 1))

        # Rate limiting: small delay between requests
        sleep 1
    done < "${promising_file}"

    log_success "Enriched ${count} targets"
}

################################################################################
# Stage 5: Selective Enumeration
################################################################################

run_gobuster() {
    local url=$1
    local wordlist=$2
    local output_file=$3
    local threads=$4

    log_info "Running gobuster on ${url}..."

    # Check if wordlist exists
    if [[ ! -f "${wordlist}" ]]; then
        log_error "Wordlist not found: ${wordlist}"
        return 1
    fi

    # Get absolute paths
    local abs_wordlist=$(realpath "${wordlist}")
    local abs_output_dir=$(realpath "$(dirname ${output_file})")

    # Run gobuster without -o flag, capture stdout
    ${DOCKER_CMD} run --rm --network=host \
        --cpus="${CPU_LIMIT}" \
        --memory="${MEMORY_LIMIT}" \
        -v "${abs_wordlist}:/wordlist.txt:ro,Z" \
        ghcr.io/oj/gobuster:latest \
        dir \
        -u "${url}" \
        -w /wordlist.txt \
        -t ${threads} \
        --timeout ${TIMEOUT}s \
        --no-error \
        --status-codes-blacklist "404" 2>&1 | tee "${output_file}" || {
            log_warning "Gobuster failed for ${url}"
            return 1
        }

    if [[ -f "${output_file}" ]] && [[ -s "${output_file}" ]]; then
        log_success "Gobuster found results for ${url}"
        return 0
    else
        log_info "Gobuster completed but found no results for ${url}"
        return 1
    fi
}


run_medium_enumeration() {
    local url=$1
    local output_dir=$2
    local wordlist=$3

    local domain
    domain=$(echo "${url}" | sed -E 's|https?://||' | sed 's|/.*||' | sed 's|:|-|g')

    local output_file="${output_dir}/raw/${domain}_gobuster.txt"

    run_gobuster "${url}" "${wordlist}" "${output_file}" "${THREADS_LOW}"
}

run_deep_enumeration() {
    local url=$1
    local output_dir=$2
    local wordlist=$3

    local domain
    domain=$(echo "${url}" | sed -E 's|https?://||' | sed 's|/.*||' | sed 's|:|-|g')

    log_info "Running deep enumeration on ${url}..."

    # Larger gobuster scan
    local gobuster_output="${output_dir}/raw/${domain}_gobuster_deep.txt"
    run_gobuster "${url}" "${wordlist}" "${gobuster_output}" "${THREADS_MEDIUM}"

    # Run nikto (lightweight scan)
    log_info "Running nikto on ${url}..."
    local nikto_output="${output_dir}/raw/${domain}_nikto.txt"

    ${DOCKER_CMD} run --rm --network=host \
        --cpus="${CPU_LIMIT}" --memory="${MEMORY_HEAVY}" \
        sullo/nikto:latest \
        -h "${url}" \
        -Tuning x6 \
        -timeout ${TIMEOUT} \
        -output /tmp/nikto.txt 2>&1 | tee "${nikto_output}" || {
            log_warning "Nikto scan failed for ${url}"
        }
}

run_enumeration() {
    local output_dir=$1
    local wordlist=$2

    log_info "Stage 5: Running selective enumeration..."

    # Medium priority targets
    if [[ -f "${output_dir}/promising.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue

            # Check if high priority (skip if yes, will be handled next)
            if grep -qF "${url}" "${output_dir}/high_priority.txt" 2>/dev/null; then
                continue
            fi

            run_medium_enumeration "${url}" "${output_dir}" "${wordlist}"
            sleep 2  # Rate limiting
        done < "${output_dir}/promising.txt"
    fi

    # High priority targets
    if [[ -f "${output_dir}/high_priority.txt" ]]; then
        while IFS= read -r url; do
            [[ -z "${url}" ]] && continue

            if [[ "${DEEP}" == "true" ]]; then
                run_deep_enumeration "${url}" "${output_dir}" "${wordlist}"
            else
                run_medium_enumeration "${url}" "${output_dir}" "${wordlist}"
            fi

            sleep 2  # Rate limiting
        done < "${output_dir}/high_priority.txt"
    fi

    log_success "Enumeration complete"
}


################################################################################
# Stage 6: Parameter Discovery
################################################################################

discover_parameters() {
    local url=$1
    local output_dir=$2

    local domain
    domain=$(echo "${url}" | sed -E 's|https?://||' | sed 's|/.*||' | sed 's|:|-|g')

    local param_file="${output_dir}/raw/${domain}_parameters.jsonl"

    log_info "Discovering parameters for ${url}..."

    # Use Python in container to parse HTML and extract forms/parameters
    ${DOCKER_CMD} run --rm --network=host \
        --cpus="0.5" --memory="512m" \
        -v "${output_dir}/raw:/output:Z" \
        python:3.11-slim \
        bash -c "
pip install requests beautifulsoup4 -q > /dev/null 2>&1
python3 << 'PYTHON_SCRIPT'
import requests
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import sys

url = '${url}'
output_file = '/output/${domain}_parameters.jsonl'

try:
    # Fetch the page
    response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
    soup = BeautifulSoup(response.text, 'html.parser')

    findings = []

    # Find all forms
    forms = soup.find_all('form')
    for idx, form in enumerate(forms):
        action = form.get('action', '')
        method = form.get('method', 'get').lower()

        # Extract input fields
        inputs = form.find_all(['input', 'textarea', 'select'])
        params = []
        for inp in inputs:
            name = inp.get('name', '')
            input_type = inp.get('type', 'text')
            if name:
                params.append({'name': name, 'type': input_type})

        if params:
            finding = {
                'url': url,
                'type': 'form',
                'form_id': idx,
                'action': action,
                'method': method,
                'parameters': params,
                'suspicious': any(
                    keyword in str(params).lower()
                    for keyword in ['search', 'id', 'user', 'query', 'cmd', 'exec', 'file', 'path']
                )
            }
            findings.append(finding)

    # Check URL parameters
    parsed = urlparse(url)
    if parsed.query:
        url_params = parse_qs(parsed.query)
        if url_params:
            finding = {
                'url': url,
                'type': 'url_params',
                'parameters': [{'name': k, 'type': 'query'} for k in url_params.keys()],
                'suspicious': any(
                    keyword in parsed.query.lower()
                    for keyword in ['id', 'file', 'page', 'url', 'redirect']
                )
            }
            findings.append(finding)

    # Write findings
    with open(output_file, 'w') as f:
        for finding in findings:
            f.write(json.dumps(finding) + '\n')

    if findings:
        print(f'Found {len(findings)} parameter vectors')
    else:
        print('No parameters found')

except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)

PYTHON_SCRIPT
" 2>/dev/null || {
        log_warning "Parameter discovery failed for ${url}"
        return 1
    }

    if [[ -f "${param_file}" ]] && [[ -s "${param_file}" ]]; then
        log_success "Found parameters for ${url}"
        return 0
    else
        return 1
    fi
}

run_parameter_discovery() {
    local output_dir=$1

    log_info "Stage 6: Discovering parameters..."

    if [[ ! -f "${output_dir}/high_priority.txt" ]]; then
        log_warning "No high-priority targets for parameter discovery"
        return 0
    fi

    local found=0
    while IFS= read -r url; do
        [[ -z "${url}" ]] && continue

        if discover_parameters "${url}" "${output_dir}"; then
            found=$((found + 1))
        fi

        sleep 1
    done < "${output_dir}/high_priority.txt"

    log_success "Parameter discovery complete: ${found} targets with parameters"
}

################################################################################
# Stage 7: Selective Vulnerability Checks
################################################################################

check_sql_injection() {
    local url=$1
    local param=$2
    local output_dir=$3

    local domain
    domain=$(echo "${url}" | sed -E 's|https?://||' | sed 's|/.*||' | sed 's|:|-|g')

    log_info "Testing SQL injection on ${url} (param: ${param})..."

    # Conservative sqlmap test
    ${DOCKER_CMD} run --rm --network=host \
        --cpus="${CPU_LIMIT}" --memory="${MEMORY_HEAVY}" \
        -v "${output_dir}/raw:/output:Z" \
        pberba/sqlmap:latest \
        -u "${url}" \
        -p "${param}" \
        --batch \
        --level=1 \
        --risk=1 \
        --threads=1 \
        --timeout=${TIMEOUT} \
        --retries=1 \
        --technique=BEUST \
        --tamper=space2comment \
        --output-dir=/output/sqlmap \
        2>&1 | tee "${output_dir}/raw/${domain}_sqlmap.txt" || {
            log_warning "SQLMap test inconclusive for ${url}"
        }
}

run_cms_checks() {
    local url=$1
    local cms=$2
    local output_dir=$3

    local domain
    domain=$(echo "${url}" | sed -E 's|https?://||' | sed 's|/.*||' | sed 's|:|-|g')

    case "${cms}" in
        *wordpress*|*WordPress*)
            log_info "Running wpscan on ${url}..."
            ${DOCKER_CMD} run --rm --network=host \
                --cpus="${CPU_LIMIT}" --memory="${MEMORY_LIMIT}" \
                wpscanteam/wpscan:latest \
                --url "${url}" \
                --enumerate vp,vt,u \
                --detection-mode aggressive \
                --max-threads 5 \
                --request-timeout ${TIMEOUT} \
                --connect-timeout ${TIMEOUT} \
                -f json \
                -o /dev/stdout 2>&1 | tee "${output_dir}/raw/${domain}_wpscan.json" || {
                    log_warning "WPScan failed for ${url}"
                }
            ;;
        *drupal*|*Drupal*)
            log_info "Running droopescan on ${url}..."
            ${DOCKER_CMD} run --rm --network=host \
                --cpus="${CPU_LIMIT}" --memory="${MEMORY_LIMIT}" \
                droope/droopescan:latest \
                scan drupal \
                -u "${url}" \
                -t ${THREADS_LOW} \
                --timeout ${TIMEOUT} \
                2>&1 | tee "${output_dir}/raw/${domain}_droopescan.txt" || {
                    log_warning "Droopescan failed for ${url}"
                }
            ;;
    esac
}

run_vulnerability_checks() {
    local output_dir=$1

    log_info "Stage 7: Running selective vulnerability checks..."

    # Only run on high-priority targets with parameters
    local checked=0

    if [[ -f "${output_dir}/scored_targets.csv" ]]; then
        # Check for CMS targets
        while IFS=',' read -r url score status title content_type server tech priority; do
            [[ "${priority}" != "high" ]] && continue
            [[ -z "${tech}" ]] && continue

            # Run CMS-specific checks
            if echo "${tech}" | grep -qiE "wordpress|drupal"; then
                run_cms_checks "${url}" "${tech}" "${output_dir}"
                checked=$((checked + 1))
            fi

        done < <(tail -n +2 "${output_dir}/scored_targets.csv")
    fi

    # Check for SQL injection only if parameters found and evidence exists
    if [[ -d "${output_dir}/raw" ]]; then
        for param_file in "${output_dir}"/raw/*_parameters.jsonl; do
            [[ ! -f "${param_file}" ]] && continue

            # Parse JSONL and check for suspicious parameters
            while IFS= read -r line; do
                if command -v jq &> /dev/null; then
                    local url suspicious
                    url=$(echo "${line}" | jq -r '.url // empty')
                    suspicious=$(echo "${line}" | jq -r '.suspicious // false')

                    if [[ "${suspicious}" == "true" ]] && [[ "${DEEP}" == "true" ]]; then
                        local params
                        params=$(echo "${line}" | jq -r '.parameters[].name' | head -1)

                        if [[ -n "${params}" ]]; then
                            check_sql_injection "${url}" "${params}" "${output_dir}"
                            checked=$((checked + 1))
                        fi
                    fi
                fi
            done < "${param_file}"
        done
    fi

    log_success "Vulnerability checks complete: ${checked} targets tested"
}

################################################################################
# Stage 8: Triage & Reporting
################################################################################

generate_sqlite_database() {
    local output_dir=$1
    local db_file="${output_dir}/findings.db"

    log_info "Generating SQLite database..."

    # Create SQL commands file
    local sql_file="${output_dir}/create_db.sql"

    cat > "${sql_file}" << 'SQL'
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT UNIQUE NOT NULL,
    score INTEGER,
    status INTEGER,
    title TEXT,
    content_type TEXT,
    server TEXT,
    technologies TEXT,
    priority TEXT,
    has_parameters BOOLEAN DEFAULT 0,
    waf_detected TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    finding_type TEXT,
    severity TEXT,
    description TEXT,
    evidence TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id)
);

CREATE INDEX IF NOT EXISTS idx_priority ON targets(priority);
CREATE INDEX IF NOT EXISTS idx_score ON targets(score);
CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity);
SQL

    # Use container to create database
    local abs_output_dir=$(realpath "${output_dir}")

    ${DOCKER_CMD} run --rm \
        -v "${abs_output_dir}:/data:Z" \
        -w /data \
        alpine:latest \
        sh -c "apk add --no-cache sqlite > /dev/null 2>&1 && sqlite3 /data/findings.db < /data/create_db.sql" || {
            log_warning "Failed to create SQLite database"
            return 1
        }

    # Import scored targets if database was created
    if [[ -f "${db_file}" ]] && [[ -f "${output_dir}/scored_targets.csv" ]]; then
        ${DOCKER_CMD} run --rm \
            -v "${abs_output_dir}:/data:Z" \
            -w /data \
            alpine:latest \
            sh -c "
                apk add --no-cache sqlite > /dev/null 2>&1
                tail -n +2 /data/scored_targets.csv | while IFS=',' read -r url score status title content_type server tech priority; do
                    sqlite3 /data/findings.db \"INSERT OR IGNORE INTO targets (url, score, status, title, content_type, server, technologies, priority) VALUES ('\${url}', \${score}, \${status}, '\${title}', '\${content_type}', '\${server}', '\${tech}', '\${priority}');\"
                done
            " || log_warning "Failed to import data into database"
    fi

    if [[ -f "${db_file}" ]]; then
        log_success "Database created at ${db_file}"
        return 0
    else
        log_warning "Database creation failed"
        return 1
    fi
}


generate_recommendations() {
    local output_dir=$1
    local rec_file="${output_dir}/recommended_actions.txt"

    log_info "Generating recommendations..."

    cat > "${rec_file}" << 'RECOMMENDATIONS'
# Web Reconnaissance - Recommended Next Steps

## Manual Verification Required
⚠️  All automated findings MUST be manually verified before reporting.

## High-Priority Targets
RECOMMENDATIONS

    if [[ -f "${output_dir}/high_priority.txt" ]]; then
        echo "" >> "${rec_file}"
        echo "### Targets requiring immediate attention:" >> "${rec_file}"
        while IFS= read -r url; do
            echo "- ${url}" >> "${rec_file}"
            echo "  Action: Manual browse, check for sensitive data exposure" >> "${rec_file}"
        done < "${output_dir}/high_priority.txt"
    fi

    cat >> "${rec_file}" << 'RECOMMENDATIONS'

## CMS-Specific Checks
- WordPress: Review wpscan results for outdated plugins/themes
- Drupal: Check droopescan output for known CVEs

## Parameter Testing
- Review parameters.jsonl for injection points
- Manually test suspicious parameters with Burp Suite
- Confirm any SQLMap findings with manual SQL injection

## Directory Enumeration Results
- Review gobuster/feroxbuster outputs for sensitive paths
- Check robots.txt disallowed paths manually
- Verify sitemap.xml for hidden endpoints

## Security Headers
- Check for missing security headers (CSP, HSTS, X-Frame-Options)
- Verify HTTPS configuration and certificate validity

## False Positive Checks
- Verify any vulnerability findings are not WAF responses
- Confirm findings work with different User-Agent strings
- Test from different IP addresses if possible

## Legal Reminders
✓ Ensure all testing is authorized
✓ Stay within defined scope
✓ Document all actions taken
✓ Follow responsible disclosure timeline
RECOMMENDATIONS

    log_success "Recommendations saved to ${rec_file}"
}

generate_final_report() {
    local output_dir=$1

    log_info "Stage 8: Generating final report..."

    # Generate SQLite database
    #if command -v sqlite3 &> /dev/null; then
    #    generate_sqlite_database"${output_dir}"
    #else
    #    log_warning "sqlite3 not available, skipping database generation"
    #fi

    # Generate recommendations
    #generate_recommendations "${output_dir}"

    # Create summary
    local summary_file="${output_dir}/SUMMARY.txt"

    cat > "${summary_file}" << SUMMARY
╔═══════════════════════════════════════════════════════════╗
║        Web Reconnaissance Pipeline - Summary              ║
╚═══════════════════════════════════════════════════════════╝

Target: ${TARGET}
Scan Date: $(date)
Output Directory: ${output_dir}

SUMMARY

    # Count results
    local total_urls high_priority medium_priority ports
    total_urls=$(wc -l < "${output_dir}/raw/http_probe.jsonl" 2>/dev/null || echo "0")
    high_priority=$(wc -l < "${output_dir}/high_priority.txt" 2>/dev/null || echo "0")
    medium_priority=$(wc -l < "${output_dir}/promising.txt" 2>/dev/null || echo "0")
    ports=$(wc -l < "${output_dir}/raw/open_ports.txt" 2>/dev/null || echo "0")

    cat >> "${summary_file}" << SUMMARY

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Statistics
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Open Ports Found:        ${ports}
HTTP Endpoints Probed:   ${total_urls}
High-Priority Targets:   ${high_priority}
Medium-Priority Targets: ${medium_priority}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Key Files
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scored Targets:          scored_targets.csv
High Priority List:      high_priority.txt
Promising Targets:       promising.txt
Database:                findings.db
Recommendations:         recommended_actions.txt

Raw Data:                raw/
Enrichment Data:         enrichment/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 Next Steps
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Review high_priority.txt for critical targets
2. Manually browse each high-priority URL
3. Read recommended_actions.txt for specific guidance
4. Query findings.db for detailed analysis
5. Verify all findings before reporting

⚠️  CRITICAL: All automated findings must be manually verified!

SUMMARY

    log_success "Summary saved to ${summary_file}"

    # Display summary
    cat "${summary_file}"
}

################################################################################
# Main Execution
################################################################################

main() {
    print_banner
    check_requirements

    # Set wordlist default
    WORDLIST="${WORDLIST:-wordlists/common.txt}"

    if [[ ! -f "${WORDLIST}" ]]; then
        log_error "Wordlist not found: ${WORDLIST}"
        exit 1
    fi

    # Create output structure
    create_output_structure "${OUTPUT_DIR}"

    # Stage 1: Port Discovery (unless skipped)
    if [[ "${SKIP_NMAP}" != "true" ]]; then
        run_nmap_discovery "${TARGET}" "${OUTPUT_DIR}" || log_warning "Port discovery failed, continuing..."
    fi

    # Stage 2: HTTP Probing
    run_httpx_probe "${TARGET}" "${OUTPUT_DIR}" || {
        log_error "HTTP probing failed, cannot continue"
        exit 1
    }

    # Stage 3: Scoring & Filtering
    score_and_filter "${OUTPUT_DIR}"

    # Stage 4: Enrichment
    run_enrichment "${OUTPUT_DIR}"

    # Stage 5: Enumeration
    run_enumeration "${OUTPUT_DIR}" "${WORDLIST}"

    # Stage 6: Parameter Discovery
    run_parameter_discovery "${OUTPUT_DIR}"

    # Stage 7: Vulnerability Checks (only in deep mode)
    if [[ "${DEEP}" == "true" ]]; then
        run_vulnerability_checks "${OUTPUT_DIR}"
    fi

    # Stage 8: Final Report
    generate_final_report "${OUTPUT_DIR}"

    log_success "Reconnaissance pipeline complete!"
    log_info "Results saved to: ${OUTPUT_DIR}"
}

# Execute main function
main
