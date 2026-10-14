#!/usr/bin/env bash
# tagcess interactive installer (F6-009). Drives deploy/ansible/site.yml one phase (tag) at a time.
#
#   deploy/install.sh [--env <name>] [--plan] [--resume] [--phase <name>] [--dry-run]
#
# - Asks for the environment settings once and writes them OUTSIDE the repo:
#   ${XDG_CONFIG_HOME:-$HOME/.config}/tagcess-install/<env>/{inventory.yml,vars.yml,state}.
#   Secrets are only file paths; the script checks that a file exists and its mode, never reads it. The tagcess secrets
#   (signing keys, service user key) are asked when the host phase starts, not with the settings: a fresh install has no
#   Zitadel service user before zitadel_seed.
# - Every run starts with the read-only preflight (--tags preflight); a blocker stops before any writing phase.
# - The mode (fresh/adopt) is proposed by preflight and confirmed by typing it (decision 8 [K]).
# - Every phase that writes runs only after the developer types "evet"; any other answer skips it and stops.
#   Phase confirmations (-e confirm_<phase>=yes) go only to that phase's call, never in bulk.
# - After each phase its guide (manual steps) is shown; the answer is recorded in the state file.
# - --dry-run runs every call with --check --diff (zitadel_seed also with zitadel_seed_apply=false), asks nothing.
# - --resume skips the phases the state file records as done.
#
# Only dependency: ansible-playbook (ANSIBLE_PLAYBOOK overrides it; the tests use a fake). Bash 3.2 compatible.
set -eu
set -o pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd -P)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd -P)
ANSIBLE_DIR="$SCRIPT_DIR/ansible"
PHASES_FILE="$ANSIBLE_DIR/group_vars/all/phases.yml"
AP=${ANSIBLE_PLAYBOOK:-ansible-playbook}

ENV_NAME=""
PLAN=0
RESUME=0
ONLY_PHASE=""
DRY_RUN=0
MODE=""

# Exit codes: 0 finished, 1 error or blocker, 3 stopped because the developer did not confirm.
EXIT_STOPPED=3

usage() {
	cat <<'EOF'
Kullanım: deploy/install.sh [--env <ad>] [--plan] [--resume] [--phase <ad>] [--dry-run]
  --env <ad>     ortam adı (ayarlar ~/.config/tagcess-install/<ad>/ altında)
  --plan         seçili kipin faz planını gösterir, hiçbir şey çalıştırmaz
  --resume       tamamlanmış fazları atlar, sıradakinden devam eder
  --phase <ad>   preflight'tan sonra yalnız bu fazı çalıştırır
  --dry-run      her çağrı --check --diff ile; onay sorulmaz, yalnız plan gösterilir
EOF
}

say() { printf '%s\n' "$*"; }
die() {
	printf 'HATA: %s\n' "$*" >&2
	exit 1
}

# ask VAR "question" [default]: one line from stdin; the default when the answer is empty.
ask() {
	local __var=$1 __q=$2 __def=${3-} __ans
	if [ -n "$__def" ]; then
		printf '%s [%s]: ' "$__q" "$__def"
	else
		printf '%s: ' "$__q"
	fi
	if ! IFS= read -r __ans; then
		printf '\n'
		die "girdi bitti (soru: $__q)"
	fi
	[ -n "$__ans" ] || __ans=$__def
	case $__ans in
	*\"* | *\\*) die "değerde \" ya da \\ olamaz: $__q" ;;
	esac
	printf -v "$__var" '%s' "$__ans"
}

# confirm "question": true only when the developer types exactly "evet".
confirm() {
	local a
	ask a "$1 (onay için evet yaz)"
	[ "$a" = "evet" ]
}

# physpath PATH: the physical absolute path (symlinks resolved) of PATH, which need not exist.
physpath() {
	local p=$1 rest=""
	case $p in /*) ;; *) p="$PWD/$p" ;; esac
	while [ ! -d "$p" ]; do
		rest="/$(basename "$p")$rest"
		p=$(dirname "$p")
	done
	printf '%s%s\n' "$(cd "$p" && pwd -P)" "$rest"
}

in_repo() {
	case "$(physpath "$1")/" in
	"$REPO_ROOT"/*) return 0 ;;
	esac
	return 1
}

expand_home() {
	case $1 in
	\~) printf '%s\n' "$HOME" ;;
	\~/*) printf '%s/%s\n' "$HOME" "${1#\~/}" ;;
	*) printf '%s\n' "$1" ;;
	esac
}

# valid_host NAME: a lowercase RFC 1123 host name with at least one dot (domain, certificate names).
valid_host() { printf '%s\n' "$1" | grep -Eqx '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+'; }

file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# --- environment files ----------------------------------------------------------------------------------
# vars.yml is an Ansible inventory file holding only all.vars, one `key: value` per line (flow style), so the
# script can read and replace single keys. Inventory vars are below set_fact: phase outputs (zitadel.json)
# can still fill ids the file leaves empty.
set_var() {
	local key=$1 val=$2 tmp="$VARS.tmp"
	{
		if [ -f "$VARS" ]; then
			grep -v "^    $key:" "$VARS"
		else
			printf 'all:\n  vars:\n'
		fi
		printf '    %s: %s\n' "$key" "$val"
	} >"$tmp"
	mv "$tmp" "$VARS"
	chmod 600 "$VARS"
}

get_var() {
	[ -f "$VARS" ] || return 0
	sed -n "s/^    $1: //p" "$VARS" | head -n 1 | sed 's/^"\(.*\)"$/\1/'
}

q() { printf '"%s"' "$1"; }

state_add() { printf '%s\n' "$*" >>"$STATE"; }
state_has() { [ -f "$STATE" ] && grep -qx "$*" "$STATE"; }

# --- preflight.json (to_nice_json: one key per line) ----------------------------------------------------
json_str() { sed -n "s/^ *\"$1\": \"\(.*\)\",\{0,1\}$/\1/p" "$PREFLIGHT_JSON" | head -n 1; }
# json_list KEY: the string items of a top-level list, one per line.
json_list() {
	awk -v k="\"$1\": [" '
		index($0, k) == 1 + match($0, /[^ ]/) - 1 && !inlist { if ($0 ~ /\[\],?$/) exit; inlist = 1; next }
		inlist && /^ *\],?$/ { exit }
		inlist { s = $0; sub(/^ *"/, "", s); sub(/",?$/, "", s); print s }
	' "$PREFLIGHT_JSON"
}
# json_component NAME: true/false from the "components" object.
json_component() {
	awk -v k="\"$1\":" '
		/"components": \{/ { inobj = 1; next }
		inobj && /^ *\},?$/ { exit }
		inobj && index($0, k) { v = $0; sub(/.*: /, "", v); sub(/,$/, "", v); print v; exit }
	' "$PREFLIGHT_JSON"
}

# --- phases.yml ------------------------------------------------------------------------------------------
# One line per phase: name|modes|writes|confirm.
phase_table() {
	sed -n 's/^  - {name: \([a-z0-9_]*\), role: [a-z0-9_]*, modes: \[\([a-z, ]*\)\], writes: \([a-z]*\), confirm: \([a-z0-9_"]*\)}$/\1|\2|\3|\4/p' "$PHASES_FILE" |
		sed 's/|""$/|/'
}

phase_in_mode() { # phase_in_mode MODES MODE
	case ", $1," in *", $2,"*) return 0 ;; esac
	return 1
}

phase_effect() {
	case $1 in
	certbot) say "Sertifika: eksikse certbot kurulur ve sertifika alınır (adopt: yalnız eksikse)." ;;
	headscale_install) say "Headscale: eksikse kurulur (adopt: yalnız eksikse)." ;;
	caddy_install) say "Caddy: eksikse kurulur, başlangıç Caddyfile yazılır (adopt: yalnız eksikse)." ;;
	tailscale_join) say "Tailscale: host'lar tailnet'e katılır (adopt: yalnız eksikse)." ;;
	zitadel_install) say "Zitadel: lab k3s'e helm ile kurulur (yalnız lab bağlamı)." ;;
	headscale_oidc) say "Headscale OIDC ayarı yazılır, Headscale yeniden başlar." ;;
	backup) say "Host'ta tüm yönetilen yolların yedeği alınır (/var/backups/tagcess-install)." ;;
	host) say "tagcess kullanıcısı, dizinler ve secret dosyaları host'a yazılır." ;;
	host_system) say "Headscale systemd drop-in'i ve sistem ayarları yazılır." ;;
	hshelper) say "hshelper ikilisi ve sudoers kuralı kurulur." ;;
	oauth2_proxy) say "oauth2-proxy config'i yazılır ve yeniden başlatılır." ;;
	caddy_ui) say "tagcess arayüz bloğu Caddy'ye eklenir ve Caddy yeniden yüklenir." ;;
	app) say "tagcess imajı, config.yaml ve compose yazılır, tagcess başlatılır." ;;
	hs_tags) say "Headscale cihaz etiketleri (tag:vpn-server vb.) atanır." ;;
	hs_hook_acl) say "Headscale policy'sine tagcess hook ACL'i eklenir." ;;
	hs_dns_path) say "Headscale extra_records yolu tagcess'in dosyasına taşınır." ;;
	g02) say "Headscale policy dosya kipinden veritabanı kipine geçer (G-02)." ;;
	k8s_access) say "Denetim makinesine k8s erişim manifesti ve komutlar yazılır; küme değişmez." ;;
	*) say "Faz $1." ;;
	esac
}

# --- ansible-playbook ------------------------------------------------------------------------------------
# run_ap ARGS...: one site.yml call with this environment's files. --dry-run adds --check --diff.
run_ap() {
	local extra=""
	[ "$DRY_RUN" = 1 ] && extra="--check --diff"
	# shellcheck disable=SC2086 # extra is two fixed flags or empty
	(cd "$ANSIBLE_DIR" && ANSIBLE_CONFIG="${ANSIBLE_CONFIG:-$ANSIBLE_DIR/ansible.cfg}" \
		"$AP" -i "$INV" -i "$VARS" site.yml $extra "$@" $MODE_EXTRA </dev/null)
}

run_preflight() {
	say ""
	say "== preflight (salt okur) =="
	if ! run_ap --tags preflight; then
		say ""
		say "Preflight engel bildirdi; host'a yazan hiçbir faz çağrılmadı."
		if [ -f "$PREFLIGHT_JSON" ]; then
			json_list blockers | while IFS= read -r b; do say "  - $b"; done
		fi
		say "Rapor: $ENV_DIR/preflight.md"
		exit 1
	fi
	[ -f "$PREFLIGHT_JSON" ] || die "preflight.json yazılmadı: $PREFLIGHT_JSON"
}

# --- secret-looking values (the guide role's patterns, in grep -E form) -----------------------------------
has_secret() {
	local f=$1 tok toks
	grep -Eq -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$f" && return 0
	grep -Eiq '(client_secret|cookie_secret|password|passwd|token|api_key|apikey|private_key)[[:space:]]*[:=][[:space:]]*[^[:space:]<{]{8,}' "$f" && return 0
	# A long mixed-case token that is not a path component.
	# Words of token, '.' and '/' characters; only a word's leading run counts (a run after '/' or '.' is a path part).
	toks=$(LC_ALL=C tr -c 'A-Za-z0-9+_./-' '\n' <"$f" | sed 's#[./].*##' | grep -E '^[A-Za-z0-9+_-]{32,}$' || true)
	while IFS= read -r tok; do
		case $tok in *[[:upper:]]*) ;; *) continue ;; esac
		case $tok in *[[:lower:]]*) ;; *) continue ;; esac
		case $tok in *[[:digit:]]*) return 0 ;; esac
	done <<<"$toks"
	return 1
}

show_guide() {
	local phase=$1 md="$ENV_DIR/guide/$1.md" js="$ENV_DIR/guide/$1.json" a
	[ -s "$md" ] || return 0
	if has_secret "$md" || { [ -f "$js" ] && has_secret "$js"; }; then
		die "guide/$phase içeriğinde secret biçimli bir değer var; gösterilmedi. Rolün guide öğesini düzelt."
	fi
	grep -q '"id":' "$js" 2>/dev/null || return 0
	say ""
	say "== Elle adımlar: $phase =="
	cat "$md"
	[ "$DRY_RUN" = 1 ] && return 0
	ask a "Elle adımları yaptın mı? (y: yaptım, s: sonra yapacağım)" s
	case $a in
	y | Y | evet) state_add "guide $phase yapildi" ;;
	*) state_add "guide $phase sonra" ;;
	esac
}

# --- questions -------------------------------------------------------------------------------------------
# ask_secret KEY "question" required|optional: a secret FILE path; checked for existence and mode, never read.
SECRET_MAP=""
ask_secret() {
	local key=$1 qs=$2 need=$3 p m
	while :; do
		ask p "$qs (dosya yolu; içerik sorulmaz)"
		if [ -z "$p" ]; then
			[ "$need" = optional ] && return 0
			say "  zorunlu"
			continue
		fi
		p=$(expand_home "$p")
		if in_repo "$p"; then
			say "  repo içinde secret dosyası olmaz: $p"
			continue
		fi
		if [ ! -f "$p" ]; then
			say "  dosya yok: $p"
			continue
		fi
		m=$(file_mode "$p")
		case $m in
		600 | 640 | 400) break ;;
		*) say "  dosya modu $m; 0600, 0640 ya da 0400 olmalı (chmod 600 $p)" ;;
		esac
	done
	SECRET_MAP="${SECRET_MAP:+$SECRET_MAP, }$(q "$key"): $(q "$p")"
	LAST_SECRET=$p
}

ask_settings() {
	local vpn_host vpn_user k8s_host domain certs vpn_ip k8s_ip ep port addr sites o2 seed list c
	say "Ortam '$ENV_NAME' için ayarlar. Secret içerikleri sorulmaz; yalnız dosya yolları."
	ask vpn_host "VPN host ssh adresi (IP ya da ad)"
	[ -n "$vpn_host" ] || die "VPN host gerekli"
	ask vpn_user "ssh kullanıcısı" root
	ask k8s_host "k8s host ssh adresi (yalnız fresh kipte tailscale_join için; boş: yok)" ""
	ask domain "Alan adı (tagcess_domain)"
	valid_host "$domain" || die "geçersiz alan adı: '$domain' (küçük harf, rakam, - ve .)"
	ask certs "Sertifika adları, virgülle (cert_names)" "$domain"
	ask vpn_ip "VPN host tailnet IP'si (boş: preflight bulur)" ""
	ask k8s_ip "k8s tailnet IP'si (k8s_tailnet_ip)" 100.64.0.5
	ask ep "Traefik giriş adı (traefik_entrypoint)" websecure
	ask port "Traefik portu (traefik_port)" 443
	case $port in '' | *[!0-9]*) die "traefik_port sayı olmalı: $port" ;; esac
	ask addr "k8s hedef adresi (k8s_target_addr)" "https://$k8s_ip:$port"
	ask sites "Caddy site dizini (caddy_sites_dir; boş: tek Caddyfile)" ""
	ask o2 "oauth2-proxy biçimi (systemd|container)" container
	case $o2 in systemd | container) ;; *) die "oauth2-proxy biçimi systemd ya da container olmalı: $o2" ;; esac
	ask seed "Site seed dosyası (site_seed_file)"
	seed=$(expand_home "$seed")
	[ -f "$seed" ] || die "seed dosyası yok: $seed"
	# The tagcess secrets (signing keys, service user key) are asked when the host phase starts (ask_host_secrets): on a
	# fresh install Zitadel does not exist yet, so the service user and the Actions target keys cannot exist now.
	SECRET_MAP=""
	LAST_SECRET=""
	ask_secret zitadel_admin_key "Zitadel yönetici anahtar dosyası (boş: yok)" optional
	local admin=$LAST_SECRET

	{
		printf 'all:\n  children:\n    vpn:\n      hosts:\n        vpn-host:\n'
		printf '          ansible_host: %s\n          ansible_user: %s\n' "$(q "$vpn_host")" "$(q "$vpn_user")"
		if [ -n "$k8s_host" ]; then
			printf '    k8s:\n      hosts:\n        k8s-host:\n'
			printf '          ansible_host: %s\n          ansible_user: %s\n' "$(q "$k8s_host")" "$(q "$vpn_user")"
		fi
	} >"$INV.tmp"
	mv "$INV.tmp" "$INV"
	chmod 600 "$INV"

	list=""
	local IFS=,
	for c in $certs; do
		c=$(printf '%s' "$c" | tr -d ' ')
		[ -n "$c" ] || continue
		valid_host "$c" || die "geçersiz sertifika adı: '$c'"
		list="${list:+$list, }$(q "$c")"
	done
	unset IFS
	rm -f "$VARS"
	set_var install_env "$(q "$ENV_NAME")"
	set_var tagcess_domain "$(q "$domain")"
	set_var cert_names "[$list]"
	set_var vpn_tailnet_ip "$(q "$vpn_ip")"
	set_var k8s_tailnet_ip "$(q "$k8s_ip")"
	set_var traefik_entrypoint "$(q "$ep")"
	set_var traefik_port "$port"
	set_var k8s_target_addr "$(q "$addr")"
	set_var caddy_sites_dir "$(q "$sites")"
	set_var oauth2_proxy_runtime "$(q "$o2")"
	set_var site_seed_file "$(q "$seed")"
	set_var zitadel_admin_key_file "$(q "$admin")"
	set_var secret_files "{$SECRET_MAP}"
	say "Yazıldı: $INV, $VARS"
}

# secret_recorded KEY: the secret_files entry KEY is already in vars.yml (an earlier run, or edited by hand).
secret_recorded() { get_var secret_files | grep -q "\"$1\": \"[^\"]"; }

# seed_produced KEY: zitadel_seed already made that secret file (its output <env>/zitadel.json names the path).
seed_produced() { [ -f "$ENV_DIR/zitadel.json" ] && grep -q "\"$1\": \"[^\"]" "$ENV_DIR/zitadel.json"; }

# ask_host_secrets: the files the host phase copies to the host (F6 fix M1). Asked when that phase starts, never earlier:
# the service user key exists only after zitadel_seed and its console guide. A signing key zitadel_seed created itself
# (Actions targets) or one already recorded is not asked again.
ask_host_secrets() {
	SECRET_MAP=$(get_var secret_files | sed 's/^{//; s/}$//')
	if ! secret_recorded webhook_signing_key && ! seed_produced webhook_signing_key; then
		ask_secret webhook_signing_key "Webhook imza anahtarı" required
	fi
	if ! secret_recorded groups_signing_key && ! seed_produced groups_signing_key; then
		ask_secret groups_signing_key "Groups imza anahtarı (boş: yok)" optional
	fi
	if ! secret_recorded zitadel_key; then
		ask_secret zitadel_key "tagcess servis kullanıcısı anahtarı (zitadel-key.json; konsolda zitadel_seed'in guide adımıyla oluşur)" required
	fi
	set_var secret_files "{$SECRET_MAP}"
}

# Production kube context words: zitadel_forbidden_context_patterns in the environment's vars.yml (a YAML flow
# list), else this default. The zitadel_install role refuses the same list with the same default.
DEFAULT_FORBIDDEN_CONTEXTS="[prod, production]"

forbidden_contexts() {
	local v
	v=$(get_var zitadel_forbidden_context_patterns)
	[ -n "$v" ] || v=$DEFAULT_FORBIDDEN_CONTEXTS
	printf '%s\n' "$v" | sed 's/^\[//; s/\]$//' | tr ',' '\n' |
		sed "s/^[[:space:]\"']*//; s/[[:space:]\"']*\$//" | tr '[:upper:]' '[:lower:]' | grep -v '^$' || true
}

# refuse_prod_context CTX: stops on an empty context or one containing a production word.
refuse_prod_context() {
	local lc p
	lc=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
	[ -n "$lc" ] || die "bu bağlam lab değil ya da boş: '$1' (üretim bağlamı reddedilir)"
	while IFS= read -r p; do
		case $lc in *"$p"*) die "bu bağlam lab değil ya da boş: '$1' (üretim bağlamı reddedilir)" ;; esac
	done <<EOF
$(forbidden_contexts)
EOF
}

# Fresh-only settings (F6-012): DNS-01 token, Zitadel install on a lab cluster only.
ask_fresh_settings() {
	local en ctx nodes list n
	SECRET_MAP=$(get_var secret_files | sed 's/^{//; s/}$//')
	ask_secret cloudflare_token "Cloudflare DNS-01 token dosyası" required
	set_var secret_files "{$SECRET_MAP}"
	ask en "Zitadel bu kurulumla lab kümesine kurulsun mu? (evet/hayır)" hayır
	if [ "$en" = evet ]; then
		ask ctx "Lab kube bağlamı (zitadel_kube_context)"
		refuse_prod_context "$ctx"
		# The role also checks the context's nodes against this list before it writes anything.
		ask nodes "Lab kümesinin düğüm adları, virgülle (zitadel_expected_nodes)"
		list=""
		for n in $(printf '%s' "$nodes" | tr ',' ' '); do
			case $n in *[!a-z0-9.-]*) die "geçersiz düğüm adı: $n" ;; esac
			list="${list:+$list, }$(q "$n")"
		done
		[ -n "$list" ] || die "düğüm adı gerekli"
		set_var zitadel_install_enabled true
		set_var zitadel_kube_context "$(q "$ctx")"
		set_var zitadel_expected_nodes "[$list]"
	else
		set_var zitadel_install_enabled false
	fi
}

# --- mode ------------------------------------------------------------------------------------------------
choose_mode() {
	local proposed core m
	proposed=$(json_str proposed_mode)
	core=$(json_list core_present | tr '\n' ' ')
	say ""
	say "Önerilen kip: ${proposed:-?}"
	if [ "$proposed" = adopt ]; then
		say "  Gerekçe: hedefte çekirdek bileşen var (${core:-tagcess}); adopt var olanı benimser, üstüne yazmaz."
	else
		say "  Gerekçe: hedefte Headscale ve Caddy yok; fresh sıfırdan kurar."
	fi
	say "  Ayrıntı: $ENV_DIR/preflight.md"
	if [ "$DRY_RUN" = 1 ]; then
		MODE=$proposed
		MODE_EXTRA="-e install_mode=$MODE"
		say "  --dry-run: önerilen kip yazılmadan kullanılıyor."
		return 0
	fi
	ask m "Kipi onaylamak için fresh ya da adopt yaz"
	case $m in
	fresh | adopt) ;;
	*)
		say "Kip onaylanmadı; host'a yazan hiçbir faz çağrılmadı."
		exit $EXIT_STOPPED
		;;
	esac
	if [ "$m" = adopt ] && [ -z "$core" ] && [ "$(json_component tagcess)" != true ]; then
		say "Hedefte Headscale ve Caddy yok: adopt burada fiilen sıfırdan kurulumdur."
		if ! confirm "Yine de adopt?"; then
			say "Kip onaylanmadı; durduruldu."
			exit $EXIT_STOPPED
		fi
		# A mode confirmation, not a phase one: the mode gate runs in every call's preflight (F6-009 [Ö]).
		set_var confirm_adopt_empty '"yes"'
	fi
	set_var install_mode "$(q "$m")"
	MODE=$m
	[ "$m" = fresh ] && ask_fresh_settings
	return 0
}

print_plan() {
	local n=0 name modes writes conf
	say ""
	say "Faz planı (kip: ${MODE:-seçilmedi}):"
	while IFS='|' read -r name modes writes conf; do
		if [ -n "$MODE" ] && ! phase_in_mode "$modes" "$MODE"; then continue; fi
		n=$((n + 1))
		printf '  %2d. %-18s yazar: %-10s %s%s\n' "$n" "$name" "$writes" "${conf:+onay: $conf}" \
			"$(state_has "done $name" && printf '  (tamam)')"
	done <<EOF
$(phase_table)
EOF
}

# --- phases ----------------------------------------------------------------------------------------------
stop_here() {
	state_add "skipped $1"
	say "Faz '$1' onaylanmadı: atlandı ve durduruldu. Devam: deploy/install.sh --env $ENV_NAME --resume"
	exit $EXIT_STOPPED
}

finish_phase() {
	state_add "done $1"
	show_guide "$1"
}

# missing_component PHASE: the component an adopt phase would add, when preflight saw it missing.
missing_component() {
	local comp=""
	case $1 in
	certbot) comp=certbot ;;
	headscale_install) comp=headscale ;;
	caddy_install) comp=caddy ;;
	tailscale_join) comp=tailscale ;;
	host) comp=docker ;;
	esac
	[ -n "$comp" ] && [ "$(json_component "$comp")" = false ] && printf '%s\n' "$comp"
	return 0
}

run_zitadel_seed() {
	local actions=false groups=false
	say ""
	say "== zitadel_seed: önce plan (Zitadel'e yazmaz) =="
	run_ap --tags zitadel_seed -e zitadel_seed_apply=false || die "zitadel_seed planı başarısız"
	if [ "$DRY_RUN" = 1 ]; then
		show_guide zitadel_seed
		return 0
	fi
	confirm "Bu plan Zitadel'e uygulansın mı?" || stop_here zitadel_seed
	if [ "$MODE" = adopt ]; then
		say "Mevcut bir Zitadel'de Actions v2 target'ları (webhook, groups) ayrıca onay ister; groups execution araçla hiç açılmaz."
		confirm "Actions target'ları oluşturulsun mu?" && actions=true
	else
		actions=true
		groups=true
	fi
	run_ap --tags zitadel_seed -e zitadel_seed_apply=true -e "zitadel_seed_create_actions=$actions" \
		-e "zitadel_groups_execution=$groups" || die "zitadel_seed başarısız; durum: $STATE"
	finish_phase zitadel_seed
}

run_phase() {
	local name=$1 writes=$2 conf=$3 comp sha
	local -a args
	args=(--tags "$name")
	say ""
	say "== $name =="
	phase_effect "$name"
	if [ "$name" = zitadel_seed ]; then
		run_zitadel_seed
		return 0
	fi
	if [ "$DRY_RUN" = 0 ] && [ "$writes" != none ]; then
		if [ -n "$conf" ]; then
			say "UYARI: bu faz ayrıca onay kapılı ($conf); onaysız yalnız planı ve elle adımları yazar."
		fi
		[ "$name" = host ] && ask_host_secrets
		if [ "$name" = g02 ]; then
			# The hash must be the policy at this moment (hs_tags/hs_hook_acl changed it): preflight again.
			run_preflight
			sha=$(json_str policy_sha256)
			[ -n "$sha" ] || die "preflight policy sha256'sını bulamadı"
			say "Policy sha256 (preflight): $sha — geçişten sonra policy veritabanında tutulur."
		fi
		comp=""
		[ "$MODE" = adopt ] && comp=$(missing_component "$name")
		if [ -n "$comp" ]; then
			say "Adopt: '$comp' hedefte yok; bu faz onu ekler."
			confirm "'$comp' eklensin mi?" || stop_here "$name"
			args+=(-e "confirm_add_missing=$comp")
		fi
		confirm "Faz '$name' host'a yazacak. Devam?" || stop_here "$name"
		[ -n "$conf" ] && args+=(-e "$conf=yes")
		[ "$name" = g02 ] && args+=(-e "expected_policy_sha256=$sha")
		if [ "$name" = oauth2_proxy ] && [ "$MODE" = adopt ]; then
			say "Çerez: bugünkü çerez korunur. Ortak _tagcess_gate çerezine (1 saat) geçiş kullanıcıları bir kez yeniden girişe zorlar."
			if confirm "Çerez tagcess profiline geçirilsin mi?"; then
				args+=(-e oauth2_proxy_cookie_profile=tagcess -e confirm_oauth2_cookie=yes)
			fi
		fi
	fi
	if ! run_ap "${args[@]}"; then
		state_add "failed $name"
		die "faz '$name' başarısız. Geri alma: docs/install.md §7. Devam: --resume"
	fi
	[ "$DRY_RUN" = 1 ] && {
		show_guide "$name"
		return 0
	}
	finish_phase "$name"
}

# --- main ------------------------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
	case $1 in
	--env)
		[ $# -ge 2 ] || die "--env bir ad ister"
		ENV_NAME=$2
		shift 2
		;;
	--plan) PLAN=1 && shift ;;
	--resume) RESUME=1 && shift ;;
	--phase)
		[ $# -ge 2 ] || die "--phase bir faz adı ister"
		ONLY_PHASE=$2
		shift 2
		;;
	--dry-run) DRY_RUN=1 && shift ;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		die "bilinmeyen seçenek: $1"
		;;
	esac
done

[ -f "$PHASES_FILE" ] || die "faz dosyası yok: $PHASES_FILE"
if [ -z "$ENV_NAME" ]; then
	ask ENV_NAME "Ortam adı (ör. lab, prod)"
fi
case $ENV_NAME in
'' | .* | *..* | */* | *[!A-Za-z0-9_.-]*) die "geçersiz ortam adı: '$ENV_NAME' (harf, rakam, _ - .; yol ayırıcı ve .. olmaz)" ;;
esac
if [ -n "$ONLY_PHASE" ] && ! phase_table | grep -q "^$ONLY_PHASE|"; then
	die "bilinmeyen faz: $ONLY_PHASE"
fi

CONFIG_HOME=${XDG_CONFIG_HOME:-$HOME/.config}
ENV_DIR="$CONFIG_HOME/tagcess-install/$ENV_NAME"
in_repo "$ENV_DIR" && die "yapılandırma dizini repo içinde olamaz: $ENV_DIR (XDG_CONFIG_HOME'u repo dışına ayarla)"
INV="$ENV_DIR/inventory.yml"
VARS="$ENV_DIR/vars.yml"
STATE="$ENV_DIR/state"
PREFLIGHT_JSON="$ENV_DIR/preflight.json"
MODE_EXTRA=""
mkdir -p "$ENV_DIR"
chmod 700 "$ENV_DIR"
umask 077

MODE=$(get_var install_mode)

if [ "$PLAN" = 1 ]; then
	[ -f "$VARS" ] || die "ortam '$ENV_NAME' henüz yok; önce deploy/install.sh --env $ENV_NAME"
	print_plan
	exit 0
fi

if [ ! -f "$INV" ] || [ ! -f "$VARS" ]; then
	[ "$RESUME" = 1 ] && die "ortam '$ENV_NAME' için kayıt yok; --resume olmadan başlat"
	ask_settings
else
	say "Ortam '$ENV_NAME': $ENV_DIR (ayarları değiştirmek için vars.yml'i düzenle)"
fi
if [ "$RESUME" = 0 ] && [ -f "$STATE" ] && grep -q '^done ' "$STATE"; then
	say "Not: önceki çalışmanın kaydı var; --resume tamamlananları atlar. Şimdi baştan (fazlar idempotent)."
fi

run_preflight
if [ -z "$MODE" ]; then
	choose_mode
	# The mode gate runs inside preflight: once more with the chosen mode.
	run_preflight
fi
print_plan
if [ -n "$ONLY_PHASE" ] && ! phase_table | grep "^$ONLY_PHASE|" | cut -d'|' -f2 | grep -q "\b$MODE\b"; then
	die "faz '$ONLY_PHASE' $MODE kipinde yok"
fi

# The phase table comes on fd 3: stdin stays the developer's answers.
while IFS='|' read -r name modes writes conf <&3; do
	[ "$name" = preflight ] && continue
	phase_in_mode "$modes" "$MODE" || continue
	if [ -n "$ONLY_PHASE" ] && [ "$name" != "$ONLY_PHASE" ]; then continue; fi
	if [ "$RESUME" = 1 ] && [ -z "$ONLY_PHASE" ] && state_has "done $name"; then
		say "-- $name: tamamlanmış, atlandı"
		continue
	fi
	run_phase "$name" "$writes" "$conf"
done 3<<EOF
$(phase_table)
EOF

say ""
if [ "$DRY_RUN" = 1 ]; then
	say "Dry-run bitti: hiçbir şey yazılmadı."
else
	say "Kurulum fazları bitti. Elle kalan adımlar: $ENV_DIR/guide/*.md · Durum: $STATE"
fi
