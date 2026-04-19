# Захардкоженное сплит тунелирование по правилам, на СУЩЕСТВУЮЩИЙ awg1 интерфейс

# Split tunneling setup for an existing AWG interface on OpenWrt
# Targets: existing interface name AWG_IF (default: awg1)
# Downloads domain list and configures ipset + routing rules to push matched domains via AWG interface

set -e

AWG_IF=${AWG_IF:-awg1}
DOMAINS_URL="https://raw.githubusercontent.com/TheReshkin/allow-domains/refs/heads/main/Russia/inside-dnsmasq-nfset.lst"
DNSMASQ_INCLUDE_DIR=${DNSMASQ_INCLUDE_DIR:-/tmp/dnsmasq.d/split-tunneling}
DNSMASQ_DOMAINS_FILE=${DNSMASQ_DOMAINS_FILE:-${DNSMASQ_INCLUDE_DIR}/split-tunneling-domains.conf}

require_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo "This script must be run as root" >&2
		exit 1
	fi
}

ensure_rt_table() {
	grep -q "99 vpn" /etc/iproute2/rt_tables || echo '99 vpn' >> /etc/iproute2/rt_tables
}

ensure_iprule() {
	if ! uci show network | grep -q "@rule.*name='mark0x1'"; then
		uci add network rule
		uci set network.@rule[-1].name='mark0x1'
		uci set network.@rule[-1].mark='0x1'
		uci set network.@rule[-1].priority='100'
		uci set network.@rule[-1].lookup='vpn'
		uci commit network
	else
		echo "network rule 'mark0x1' already exists"
	fi
}

install_hotplug_route() {
	cat << EOF > /etc/hotplug.d/iface/30-vpnroute
#!/bin/sh

sleep 2
ip route add table vpn default dev ${AWG_IF} 2>/dev/null || true
EOF
	chmod +x /etc/hotplug.d/iface/30-vpnroute
	cp /etc/hotplug.d/iface/30-vpnroute /etc/hotplug.d/net/30-vpnroute 2>/dev/null || true
	# Also add the route immediately in case the interface is already up
	ip route add table vpn default dev ${AWG_IF} 2>/dev/null || true
	echo "VPN routing table: $(ip route show table vpn)"
}

install_dnsmasq_full() {
	# OpenWrt 25 uses apk instead of opkg
	if apk info --installed dnsmasq-full >/dev/null 2>&1; then
		echo "dnsmasq-full already installed"
		return 0
	fi
	echo "Installing dnsmasq-full (replaces stock dnsmasq with nftset support)..."
	apk update
	# apk handles the dnsmasq -> dnsmasq-full replacement atomically
	apk add dnsmasq-full
	# apk puts new default config at dhcp.apk-new; preserve our UCI-managed config
	[ -f /etc/config/dhcp.apk-new ] && rm -f /etc/config/dhcp.apk-new
	echo "dnsmasq-full installed"
}

ensure_firewall_ipset_and_rule() {
	if ! uci show firewall | grep -q "@ipset.*name='vpn_domains'"; then
		uci add firewall ipset
		uci set firewall.@ipset[-1].name='vpn_domains'
		uci set firewall.@ipset[-1].match='dst_net'
		uci commit firewall
		echo "Created firewall ipset 'vpn_domains'"
	else
		echo "firewall ipset 'vpn_domains' already exists"
	fi

	if ! uci show firewall | grep -q "@rule.*name='mark_domains'"; then
		uci add firewall rule
		uci set firewall.@rule[-1]=rule
		uci set firewall.@rule[-1].name='mark_domains'
		uci set firewall.@rule[-1].src='lan'
		uci set firewall.@rule[-1].dest='*'
		uci set firewall.@rule[-1].proto='all'
		uci set firewall.@rule[-1].ipset='vpn_domains'
		uci set firewall.@rule[-1].set_mark='0x1'
		uci set firewall.@rule[-1].target='MARK'
		uci set firewall.@rule[-1].family='ipv4'
		uci commit firewall
		echo "Created firewall rule 'mark_domains'"
	else
		echo "firewall rule 'mark_domains' already exists"
	fi
	# Reload firewall so nftset is actually created in nftables
	echo "Reloading firewall..."
	/etc/init.d/firewall reload
}

install_nft_prerouting() {
	# fw4 (nftables) marks packets in the 'forward' chain - AFTER the routing decision.
	# For policy routing to work for LAN clients, we must mark packets in PREROUTING,
	# before the kernel makes the routing decision.
	# /etc/nftables.d/*.nft files are included by fw4 on every reload.
	mkdir -p /etc/nftables.d
	cat << 'NFT' > /etc/nftables.d/99-split-tunneling.nft
# Included inside `table inet fw4 {}` by fw4 — no `add` prefix, no table wrapper.

# Mark LAN client packets BEFORE the routing decision (prerouting).
chain split_tunneling_pre {
	type filter hook prerouting priority mangle;
	iifname != "lo" ip daddr @vpn_domains meta mark set 0x00000001
}

# Mark packets originating FROM THE ROUTER ITSELF (output hook).
# Must use 'type route' so the mark affects the routing decision.
chain split_tunneling_out {
	type route hook output priority mangle;
	ip daddr @vpn_domains meta mark set 0x00000001
}
NFT
	echo "Installed nftables prerouting rule (/etc/nftables.d/99-split-tunneling.nft)"
	# Reload firewall to apply the new prerouting chain together with the ipset
	echo "Reloading firewall..."
	/etc/init.d/firewall reload
	# Verify the chain is active
	if nft list chain inet fw4 split_tunneling_pre >/dev/null 2>&1; then
		echo "Prerouting chain active: $(nft list chain inet fw4 split_tunneling_pre | head -4)"
	else
		echo "WARNING: prerouting chain not found after reload - check /etc/nftables.d/99-split-tunneling.nft"
	fi
}

ensure_firewall_zone() {
	# Without a zone for awg1 and a lan->zone forwarding rule, fw4 REJECT-s forwarded packets
	# even when the routing table is correct.
	local ZONE_NAME="vpntunnel"

	if uci show firewall | grep -q "@zone.*name='${ZONE_NAME}'"; then
		echo "firewall zone '${ZONE_NAME}' already exists"
	else
		echo "Creating firewall zone '${ZONE_NAME}' for ${AWG_IF}..."
		uci add firewall zone
		uci set firewall.@zone[-1].name="${ZONE_NAME}"
		uci set firewall.@zone[-1].device="${AWG_IF}"
		uci set firewall.@zone[-1].forward='REJECT'
		uci set firewall.@zone[-1].output='ACCEPT'
		uci set firewall.@zone[-1].input='REJECT'
		uci set firewall.@zone[-1].masq='1'
		uci set firewall.@zone[-1].mtu_fix='1'
		uci set firewall.@zone[-1].family='ipv4'
		uci commit firewall
		echo "Created zone '${ZONE_NAME}'"
	fi

	if uci show firewall | grep -q "@forwarding.*name='${ZONE_NAME}-lan'"; then
		echo "firewall forwarding '${ZONE_NAME}-lan' already exists"
	else
		echo "Creating firewall forwarding lan -> ${ZONE_NAME}..."
		uci add firewall forwarding
		uci set firewall.@forwarding[-1]=forwarding
		uci set firewall.@forwarding[-1].name="${ZONE_NAME}-lan"
		uci set firewall.@forwarding[-1].src='lan'
		uci set firewall.@forwarding[-1].dest="${ZONE_NAME}"
		uci set firewall.@forwarding[-1].family='ipv4'
		uci commit firewall
		echo "Created forwarding lan -> ${ZONE_NAME}"
	fi
}

configure_dnsmasq_confdir() {
	# Enable a dedicated include dir only after getdomains writes a valid config file.
	if uci -q get dhcp.@dnsmasq[0].confdir >/dev/null; then
		CURDIR=$(uci get dhcp.@dnsmasq[0].confdir)
	else
		CURDIR=""
	fi
	if [ "$CURDIR" != "$DNSMASQ_INCLUDE_DIR" ]; then
		uci set dhcp.@dnsmasq[0].confdir="$DNSMASQ_INCLUDE_DIR"
		uci commit dhcp
		echo "Set dnsmasq confdir to $DNSMASQ_INCLUDE_DIR"
	fi
	mkdir -p "$DNSMASQ_INCLUDE_DIR"
}

install_getdomains_service() {
	rm -f /tmp/dnsmasq.d/domains.lst /tmp/dnsmasq.d/domains.raw /tmp/dnsmasq.d/domains.new 2>/dev/null || true
	mkdir -p "$DNSMASQ_INCLUDE_DIR"
	cat << 'SH' > /etc/init.d/getdomains
#!/bin/sh /etc/rc.common

START=99

detect_dnsmasq_feature() {
	if dnsmasq -v 2>&1 | grep -qw nftset; then
		echo nftset
		return 0
	fi

	if dnsmasq -v 2>&1 | grep -qw ipset; then
		echo ipset
		return 0
	fi

	return 1
}

convert_nftset_to_ipset() {
	input_file="$1"
	output_file="$2"
	awk '
		BEGIN {
			prefix = "nftset=/";
		}
		index($0, prefix) == 1 {
			entry = substr($0, length(prefix) + 1);
			split(entry, parts, "/");
			domain = parts[1];
			gsub(/^\./, "", domain);
			if (domain != "") {
				print "ipset=/" domain "/vpn_domains";
			}
		}
	' "$input_file" > "$output_file"
}

build_domains_file() {
	raw_file="$1"
	output_file="$2"
	feature=$(detect_dnsmasq_feature) || return 1

	case "$feature" in
		nftset)
			cp "$raw_file" "$output_file"
			;;
		ipset)
			convert_nftset_to_ipset "$raw_file" "$output_file"
			;;
		esac

	[ -s "$output_file" ]
}

validate_domains_file() {
	config_file="$1"
	dnsmasq --test --conf-file="$config_file" >/dev/null 2>&1
}

start() {
		DOMAINS_URL="$DOMAINS_URL"
		DNSMASQ_INCLUDE_DIR="$DNSMASQ_INCLUDE_DIR"
		DNSMASQ_DOMAINS_FILE="$DNSMASQ_DOMAINS_FILE"
		mkdir -p "$DNSMASQ_INCLUDE_DIR"
		tmp_raw="${DNSMASQ_INCLUDE_DIR}/domains.raw"
		tmp_conf="${DNSMASQ_INCLUDE_DIR}/domains.new"
		count=0

		while true; do
				if curl -fsS --max-time 10 "$DOMAINS_URL" -o "$tmp_raw"; then
						break
				fi
				count=$((count+1))
				echo "Failed to download domains (attempt $count). Retrying..."
				sleep 5
				if [ "$count" -gt 6 ]; then
						echo "Giving up after $count attempts"
						return 1
				fi
		done

		if ! build_domains_file "$tmp_raw" "$tmp_conf"; then
				echo "dnsmasq has neither nftset nor ipset support, or conversion produced an empty file"
				return 1
		fi

		if ! validate_domains_file "$tmp_conf"; then
				echo "Generated domains config failed validation: $tmp_conf"
				rm -f "$tmp_conf"
				return 1
		fi

		mv "$tmp_conf" "$DNSMASQ_DOMAINS_FILE"
		/etc/init.d/dnsmasq restart
}

SH
	# Inject runtime values into the generated init script.
	sed -i "s|DOMAINS_URL=\"\$DOMAINS_URL\"|DOMAINS_URL=\"${DOMAINS_URL}\"|g" /etc/init.d/getdomains || true
	sed -i "s|DNSMASQ_INCLUDE_DIR=\"\$DNSMASQ_INCLUDE_DIR\"|DNSMASQ_INCLUDE_DIR=\"${DNSMASQ_INCLUDE_DIR}\"|g" /etc/init.d/getdomains || true
	sed -i "s|DNSMASQ_DOMAINS_FILE=\"\$DNSMASQ_DOMAINS_FILE\"|DNSMASQ_DOMAINS_FILE=\"${DNSMASQ_DOMAINS_FILE}\"|g" /etc/init.d/getdomains || true
	chmod +x /etc/init.d/getdomains
	/etc/init.d/getdomains enable 2>/dev/null || true
	/etc/init.d/getdomains start || true
}

restart_network_services() {
	/etc/init.d/dnsmasq restart || true
	/etc/init.d/network restart || true
}

main() {
	require_root
	echo "Configuring split-tunneling for interface ${AWG_IF}"
	ensure_rt_table
	ensure_iprule
	install_hotplug_route
	ensure_firewall_ipset_and_rule
	ensure_firewall_zone
	install_nft_prerouting
	install_dnsmasq_full
	configure_dnsmasq_confdir
	install_getdomains_service
	restart_network_services
	echo "Done. Domains will be downloaded to /tmp/dnsmasq.d/domains.lst and matched via ipset 'vpn_domains'"
}

main "$@"

