# shellcheck shell=bash
# F5 lab connection settings. Copy it OUTSIDE the repo (e.g. ~/f5-env.sh), fill in, and source it from bash.
# Only addresses and the ssh key PATH belong here, never a key, token or password.
export VPN_IP=203.0.113.10          # lab-vpn public IP (Headscale, Caddy, tagcess, oauth2-proxy)
export K8S_IP=203.0.113.20          # lab-k8s public IP (k3s, Zitadel, demo apps)
export SSH_KEY=~/.ssh/id_ed25519    # path to the ssh key that reaches both hosts as root
export REMOTE_SRC=/root/f5/src      # where deploy.sh puts the source on lab-vpn
H() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "root@$VPN_IP" "$@"; }
K() { ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "root@$K8S_IP" "$@"; }
