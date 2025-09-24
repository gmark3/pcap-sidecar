// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package transformer

import (
	"net/netip"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/btree"
	"github.com/segmentio/fasthash/fnv1a"
	"github.com/wissance/stringFormatter"
)

type (
	TCPFlag  string
	TCPFlags []uint8

	L3Proto uint8

	L4Proto uint8

	pcapL3Filters struct {
		// filter IPs in O(log N)
		networks4 *btree.BTreeG[netip.Prefix]
		networks6 *btree.BTreeG[netip.Prefix]
		protos    mapset.Set[uint8]
	}

	pcapL4Filters struct {
		// filter ports and flags in O(1)
		ports   mapset.Set[uint16]
		noPorts mapset.Set[uint16]
		flags   uint8
		protos  mapset.Set[uint8]
	}

	pcapFilters struct {
		l3        *pcapL3Filters
		l4        *pcapL4Filters
		noSockets mapset.Set[uint64]
	}

	PcapFilters interface {
		HasL3Protos() bool
		HasIPs() bool
		HasIPv4s() bool
		HasIPv6s() bool

		HasL4Protos() bool
		HasTCPflags() bool
		HasL4Addrs() bool

		AllowsL3Proto(*uint8) bool
		AllowsIP(*netip.Addr) bool
		AllowsIPv4() bool
		AllowsIPv4Addr(*netip.Addr) bool
		AllowsIPv4Bytes([4]byte) bool
		AllowsIPv6() bool
		AllowsIPv6Addr(*netip.Addr) bool
		AllowsIPv6Bytes([16]byte) bool

		AllowsL4Proto(*uint8) bool
		AllowsTCP() bool
		AllowsUDP() bool
		AllowsL4Addr(*uint16) bool
		AllowsAnyL4Addr(...uint16) bool
		DeniesAnyL4Addr(...uint16) bool

		AllowsSocket(*netip.Addr, *uint16, *netip.Addr, *uint16) bool
		DeniesSocket(*netip.Addr, *uint16, *netip.Addr, *uint16) bool

		AllowsAnyTCPflags(*uint8) bool
	}

	Addr netip.Addr
)

func (f *pcapFilters) hashAddrAndPort(
	addr *netip.Addr,
	port *uint16,
) *uint64 {
	hash := fnv1a.HashBytes64(addr.AsSlice())
	hash += uint64(*port)
	return &hash
}

func (f *pcapFilters) hashAddrPort(
	addrPort *netip.AddrPort,
) *uint64 {
	addr := addrPort.Addr()
	port := addrPort.Port()
	return f.hashAddrAndPort(&addr, &port)
}

func (f *pcapFilters) hash2tuple(
	ipAndPort string,
) (*uint64, bool) {
	addrPort, err := netip.ParseAddrPort(ipAndPort)
	if err != nil {
		return nil, false
	}
	return f.hashAddrPort(&addrPort), true
}

func (f *pcapFilters) hashUint64s(
	hashes ...*uint64,
) *uint64 {
	hash := uint64(0)
	for _, h := range hashes {
		// addition is commutative:
		//   - no matter the order of the inputs:
		//     - this function always returns the same hash.
		hash += *h
	}
	hash = fnv1a.HashUint64(hash)
	return &hash
}

func (f *pcapFilters) hashSocketFrom2tuples(
	local string, remote string,
) (*uint64, bool) {
	localHash, localOK := f.hash2tuple(local)
	remoteHash, remoteOK := f.hash2tuple(remote)
	if !localOK || !remoteOK {
		return nil, false
	}
	return f.hashUint64s(localHash, remoteHash), true
}

func (f *pcapFilters) hashSocketFromAddrsAndPorts(
	srcAddr *netip.Addr, srcPort *uint16,
	dstAddr *netip.Addr, dstPort *uint16,
) *uint64 {
	srcHash := f.hashAddrAndPort(srcAddr, srcPort)
	dstHash := f.hashAddrAndPort(dstAddr, dstPort)
	return f.hashUint64s(srcHash, dstHash)
}

func (flag *TCPFlag) materialize() uint8 {
	_flag := string(*flag)
	if f, ok := tcpFlags[_flag]; ok {
		return f
	}
	return uint8(tcpFlagNil)
}

func mergeTCPFlags(flags ...TCPFlag) uint8 {
	mergedFlags := uint8(0)
	for _, flag := range flags {
		mergedFlags |= flag.materialize()
	}
	return mergedFlags
}

func (f *pcapFilters) addNetwork(
	networks *btree.BTreeG[netip.Prefix],
	isIPv6 bool, ipRange string,
) {
	if prefix, err := netip.ParsePrefix(ipRange); err == nil {
		if isIPv6 && prefix.Addr().Is6() ||
			!isIPv6 && prefix.Addr().Is4() {
			networks.ReplaceOrInsert(prefix)
		}
	}
}

func (f *pcapFilters) addNetworks(
	networks *btree.BTreeG[netip.Prefix],
	isIPv6 bool, ipRanges ...string,
) {
	for _, ipRange := range ipRanges {
		f.addNetwork(networks, isIPv6, ipRange)
	}
}

/* methods for filter's users */

func (flag *TCPFlag) ToUint8() uint8 {
	return flag.materialize()
}

func (f *pcapFilters) AddIPv4(IPv4 string) {
	f.addNetwork(f.l3.networks4, false /* isIPv6 */, stringFormatter.Format("{0}/32", IPv4))
}

func (f *pcapFilters) AddIPv4s(IPv4s ...string) {
	for _, IPv4 := range IPv4s {
		f.AddIPv4(IPv4)
	}
}

func (f *pcapFilters) AddIPv4Range(IPv4Range string) {
	f.addNetwork(f.l3.networks4, false /* isIPv6 */, IPv4Range)
}

func (f *pcapFilters) AddIPv4Ranges(IPv4Ranges ...string) {
	for _, IPv4Range := range IPv4Ranges {
		f.AddIPv4Range(IPv4Range)
	}
}

func (f *pcapFilters) AddIPv6(IPv6 string) {
	f.addNetwork(f.l3.networks6, true /* isIPv6 */, stringFormatter.Format("{0}/128", IPv6))
}

func (f *pcapFilters) AddIPv6s(IPv6s ...string) {
	for _, IPv6 := range IPv6s {
		f.AddIPv6(IPv6)
	}
}

func (f *pcapFilters) AddIPv6Range(IPv6Range string) {
	f.addNetwork(f.l3.networks6, true /* isIPv6 */, IPv6Range)
}

func (f *pcapFilters) AddIPv6Ranges(IPv6Ranges ...string) {
	for _, IPv6Range := range IPv6Ranges {
		f.AddIPv6Range(IPv6Range)
	}
}

func (f *pcapFilters) AddPort(port uint16) {
	f.l4.ports.Add(port)
}

func (f *pcapFilters) AddPorts(ports ...uint16) {
	for _, port := range ports {
		f.AddPort(port)
	}
}

func (f *pcapFilters) DenyPort(port uint16) {
	f.l4.noPorts.Add(port)
}

func (f *pcapFilters) DenyPorts(ports ...uint16) {
	for _, port := range ports {
		f.DenyPort(port)
	}
}

func (f *pcapFilters) AllowPort(port uint16) {
	f.l4.noPorts.Remove(port)
}

func (f *pcapFilters) AllowPorts(ports ...uint16) {
	for _, port := range ports {
		f.AllowPort(port)
	}
}

func (f *pcapFilters) AddTCPFlags(flags ...TCPFlag) {
	for _, flag := range flags {
		f.l4.flags |= flag.materialize()
	}
}

func (f *pcapFilters) CombineAndAddTCPFlags(flag ...TCPFlag) {
	f.l4.flags |= mergeTCPFlags(flag...)
}

func (f *pcapFilters) addProtos(
	protosSet mapset.Set[uint8],
	protos ...uint8,
) {
	for _, proto := range protos {
		protosSet.Add(proto)
	}
}

func (f *pcapFilters) AddL3Proto(proto L3Proto) {
	f.l3.protos.Add(uint8(proto))
}

func (f *pcapFilters) AddL3Protos(protos ...L3Proto) {
	for _, proto := range protos {
		f.AddL3Proto(proto)
	}
}

func (f *pcapFilters) AddL4Proto(proto L4Proto) {
	f.l4.protos.Add(uint8(proto))
}

func (f *pcapFilters) AddL4Protos(protos ...L4Proto) {
	for _, proto := range protos {
		f.AddL4Proto(proto)
	}
}

func (f *pcapFilters) updateNoSockets(
	local string,
	remote string,
	allowed bool,
) bool {
	if hash, ok := f.hashSocketFrom2tuples(local, remote); ok {
		if allowed {
			f.noSockets.Remove(*hash)
		} else {
			f.noSockets.Add(*hash)
		}
		return ok
	}
	return false
}

func (f *pcapFilters) AllowSocket(
	local string, remote string,
) bool {
	return f.updateNoSockets(local, remote, true /* allowed */)
}

func (f *pcapFilters) DenySocket(
	local string, remote string,
) bool {
	return f.updateNoSockets(local, remote, false /* allowed */)
}

/* methods for fulter's consumers */
/* methods to check if a packet is allowed */

func (f *pcapFilters) HasL3Protos() bool {
	return !f.l3.protos.IsEmpty()
}

func (f *pcapFilters) HasIPv4s() bool {
	return f.l3.networks4.Len() > 0
}

func (f *pcapFilters) HasIPv6s() bool {
	return f.l3.networks6.Len() > 0
}

func (f *pcapFilters) HasIPs() bool {
	return f.HasIPv4s() || f.HasIPv6s()
}

func (f *pcapFilters) AllowsL3Proto(proto *uint8) bool {
	return f.l3.protos.ContainsOne(*proto)
}

func (f *pcapFilters) AllowsIPv4() bool {
	return f.l3.protos.ContainsOne(0x04)
}

func (f *pcapFilters) AllowsIPv6() bool {
	return f.l3.protos.Contains(0x29)
}

func (f *pcapFilters) allowsIPaddr(
	networks *btree.BTreeG[netip.Prefix],
	network *netip.Prefix,
) bool {
	return networks.Has(*network)
}

func (f *pcapFilters) AllowsIPv4Addr(ip4 *netip.Addr) bool {
	prefix := netip.PrefixFrom(*ip4, 32)
	return f.allowsIPaddr(f.l3.networks4, &prefix)
}

func (f *pcapFilters) AllowsIPv4Bytes(ip4 [4]byte) bool {
	IPv4 := netip.AddrFrom4(ip4)
	return f.AllowsIPv4Addr(&IPv4)
}

func (f *pcapFilters) AllowsIPv6Addr(ip6 *netip.Addr) bool {
	prefix := netip.PrefixFrom(*ip6, 128)
	return f.allowsIPaddr(f.l3.networks6, &prefix)
}

func (f *pcapFilters) AllowsIPv6Bytes(ip6 [16]byte) bool {
	IPv6 := netip.AddrFrom16(ip6)
	return f.AllowsIPv4Addr(&IPv6)
}

func (f *pcapFilters) AllowsIP(ip *netip.Addr) bool {
	if ip.Is4() {
		return f.AllowsIPv4Addr(ip)
	}
	return f.AllowsIPv6Addr(ip)
}

func (f *pcapFilters) HasL4Protos() bool {
	return !f.l4.protos.IsEmpty()
}

func (f *pcapFilters) AllowsL4Proto(proto *uint8) bool {
	return f.l4.protos.ContainsOne(*proto)
}

func (f *pcapFilters) AllowsTCP() bool {
	return f.l4.protos.ContainsOne(0x06)
}

func (f *pcapFilters) AllowsUDP() bool {
	return f.l4.protos.ContainsOne(0x11)
}

func (f *pcapFilters) HasL4Addrs() bool {
	return !f.l4.ports.IsEmpty() || !f.l4.noPorts.IsEmpty()
}

func (f *pcapFilters) AllowsL4Addr(port *uint16) bool {
	return !f.l4.noPorts.ContainsOne(*port) && (f.l4.ports.IsEmpty() || f.l4.ports.ContainsOne(*port))
}

func (f *pcapFilters) AllowsAnyL4Addr(ports ...uint16) bool {
	return !f.DeniesAnyL4Addr(ports...) && (f.l4.ports.IsEmpty() || f.l4.ports.ContainsAny(ports...))
}

func (f *pcapFilters) DeniesAnyL4Addr(ports ...uint16) bool {
	return !f.l4.noPorts.IsEmpty() && f.l4.noPorts.ContainsAny(ports...)
}

func (f *pcapFilters) HasTCPflags() bool {
	return f.l4.flags > tcpFlagNil
}

func (f *pcapFilters) AllowsAnyTCPflags(flags *uint8) bool {
	return (*flags & f.l4.flags) > tcpFlagNil
}

func (f *pcapFilters) DeniesSocket(
	srcAddr *netip.Addr, srcPort *uint16,
	dstAddr *netip.Addr, dstPort *uint16,
) bool {
	hash := f.hashSocketFromAddrsAndPorts(srcAddr, srcPort, dstAddr, dstPort)
	return !f.noSockets.IsEmpty() && f.noSockets.ContainsOne(*hash)
}

func (f *pcapFilters) AllowsSocket(
	srcAddr *netip.Addr, srcPort *uint16,
	dstAddr *netip.Addr, dstPort *uint16,
) bool {
	return !f.DeniesSocket(srcAddr, srcPort, dstAddr, dstPort)
}

func ipLessThanFunc(a, b netip.Prefix) bool {
	if a.Overlaps(b) {
		return false
	}
	return a.Addr().Less(b.Addr())
}

func NewPcapFilters() *pcapFilters {
	return &pcapFilters{
		l3: &pcapL3Filters{
			networks4: btree.NewG[netip.Prefix](2, ipLessThanFunc),
			networks6: btree.NewG[netip.Prefix](2, ipLessThanFunc),
			protos:    mapset.NewSet[uint8](),
		},
		l4: &pcapL4Filters{
			ports:   mapset.NewSet[uint16](),
			noPorts: mapset.NewSet[uint16](),
			flags:   uint8(tcpFlagNil),
			protos:  mapset.NewSet[uint8](),
		},
		noSockets: mapset.NewSet[uint64](),
	}
}
