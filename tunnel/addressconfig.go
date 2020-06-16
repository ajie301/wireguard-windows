/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019 WireGuard LLC. All Rights Reserved.
 */

package tunnel

import (
	"bytes"
	"log"
	"net"
	"sort"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/firewall"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

var excludued_ip_route_set []winipcfg.MibIPforwardRow2

func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []net.IPNet) {
	if len(addresses) == 0 {
		return
	}
	includedInAddresses := func(a net.IPNet) bool {
		// TODO: this makes the whole algorithm O(n^2). But we can't stick net.IPNet in a Go hashmap. Bummer!
		for _, addr := range addresses {
			ip := addr.IP
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			mA, _ := addr.Mask.Size()
			mB, _ := a.Mask.Size()
			if bytes.Equal(ip, a.IP) && mA == mB {
				return true
			}
		}
		return false
	}
	interfaces, err := winipcfg.GetAdaptersAddresses(family, winipcfg.GAAFlagDefault)
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.OperStatus == winipcfg.IfOperStatusUp {
			continue
		}
		for address := iface.FirstUnicastAddress; address != nil; address = address.Next {
			ip := address.Address.IP()
			ipnet := net.IPNet{IP: ip, Mask: net.CIDRMask(int(address.OnLinkPrefixLength), 8*len(ip))}
			if includedInAddresses(ipnet) {
				log.Printf("Cleaning up stale address %s from interface ‘%s’", ipnet.String(), iface.FriendlyName())
				iface.LUID.DeleteIPAddress(ipnet)
			}
		}
	}
}

func configureInterface(family winipcfg.AddressFamily, conf *conf.Config, tun *tun.NativeTun) error {
	luid := winipcfg.LUID(tun.LUID())

	estimatedRouteCount := 0
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.AllowedIPs)
	}
	routes := make([]winipcfg.RouteData, 0, estimatedRouteCount)
	addresses := make([]net.IPNet, len(conf.Interface.Addresses))
	var haveV4Address, haveV6Address bool
	for i, addr := range conf.Interface.Addresses {
		addresses[i] = addr.IPNet()
		if addr.Bits() == 32 {
			haveV4Address = true
		} else if addr.Bits() == 128 {
			haveV6Address = true
		}
	}

	foundDefault4 := false
	foundDefault6 := false
	for _, peer := range conf.Peers {
		for _, allowedip := range peer.AllowedIPs {
			if (allowedip.Bits() == 32 && !haveV4Address) || (allowedip.Bits() == 128 && !haveV6Address) {
				continue
			}
			route := winipcfg.RouteData{
				Destination: allowedip.IPNet(),
				Metric:      0,
			}
			if allowedip.Bits() == 32 {
				if allowedip.Cidr == 0 {
					foundDefault4 = true
				}
				route.NextHop = net.IPv4zero
			} else if allowedip.Bits() == 128 {
				if allowedip.Cidr == 0 {
					foundDefault6 = true
				}
				route.NextHop = net.IPv6zero
			}
			routes = append(routes, route)
		}
	}

	err := luid.SetIPAddressesForFamily(family, addresses)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		cleanupAddressesOnDisconnectedInterfaces(family, addresses)
		err = luid.SetIPAddressesForFamily(family, addresses)
	}
	if err != nil {
		return err
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Metric < routes[j].Metric ||
			bytes.Compare(routes[i].NextHop, routes[j].NextHop) == -1 ||
			bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP) == -1 ||
			bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask) == -1
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	err = luid.SetRoutesForFamily(family, deduplicatedRoutes)
	if err != nil {
		return nil
	}

	ipif, err := luid.IPInterface(family)
	if err != nil {
		return err
	}
	if conf.Interface.MTU > 0 {
		ipif.NLMTU = uint32(conf.Interface.MTU)
		tun.ForceMTU(int(ipif.NLMTU))
	}
	if family == windows.AF_INET {
		if foundDefault4 {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
	} else if family == windows.AF_INET6 {
		if foundDefault6 {
			ipif.UseAutomaticMetric = false
			ipif.Metric = 0
		}
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
	}
	err = ipif.Set()
	if err != nil {
		return err
	}

	err = luid.SetDNSForFamily(family, conf.Interface.DNS)
	if err != nil {
		return err
	}

	return nil
}

//get default net interface info (interface ID:luidDefault  gateway:NextTop  metric  )
func getDefaultInterface(family winipcfg.AddressFamily, tun *tun.NativeTun) (winipcfg.LUID, uint32, winipcfg.RawSockaddrInet, error) {
	r, err := winipcfg.GetIPForwardTable2(family)
	luid := winipcfg.LUID(tun.LUID())
	var nextTop winipcfg.RawSockaddrInet

	if err != nil {
		return luid, uint32(0), nextTop, err
	}

	lowestMetric := ^uint32(0)      // Zero is "unspecified", which for IP_UNICAST_IF resets the value, which is what we want.
	luidDefault := winipcfg.LUID(0) // Hopefully luid zero is unspecified, but hard to find docs saying so.

	for i := range r {
		if r[i].DestinationPrefix.PrefixLength != 0 || r[i].InterfaceLUID == luid {
			continue
		}
		ifrow, err := r[i].InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		if r[i].Metric < lowestMetric {
			lowestMetric = r[i].Metric
			luidDefault = r[i].InterfaceLUID
			nextTop = r[i].NextHop
		}
	}
	//setting route tables needs these paramters
	return luidDefault, lowestMetric, nextTop, nil
}

func AddDefaultRoute(family winipcfg.AddressFamily, tun *tun.NativeTun, destination net.IPNet, nextHop net.IP, metric uint32) error {
	row := &winipcfg.MibIPforwardRow2{}
	row.Init()
	var NextTop winipcfg.RawSockaddrInet
	row.InterfaceLUID, metric, NextTop, _ = getDefaultInterface(family, tun)
	nextHop = NextTop.IP()
	err := row.DestinationPrefix.SetIPNet(destination)
	if err != nil {
		return err
	}
	err = row.NextHop.SetIP(nextHop, 0)
	if err != nil {
		return err
	}
	row.Metric = metric
	// record the excluded ip route table to delete when loginning out
	excludued_ip_route_set = append(excludued_ip_route_set, *row)
	err = winipcfg.CreateDefaultRoute(row)
	if err != nil {
		return err
	}
	return nil
}

func DeleteDefaultRoute() error {
	for _, row := range excludued_ip_route_set {
		err := winipcfg.DeleteDefaultRoute(&row)
		if err != nil {
		    excludued_ip_route_set = excludued_ip_route_set[:0]
			return err
		}
	}
	excludued_ip_route_set = excludued_ip_route_set[:0]
	return nil
}

func SetDefaultRoutesForFamily(family winipcfg.AddressFamily, tun *tun.NativeTun, routesData []*winipcfg.RouteData) error {
	for _, rd := range routesData {
		asV4 := rd.Destination.IP.To4()
		if asV4 == nil && family == windows.AF_INET {
			continue
		} else if asV4 != nil && family == windows.AF_INET6 {
			continue
		}
		err := AddDefaultRoute(family, tun, rd.Destination, rd.NextHop, rd.Metric)
		if err != nil {
			return err
		}
	}
	return nil
}

func configureDefaultInterface(family winipcfg.AddressFamily, conf *conf.Config, tun *tun.NativeTun) error {

	estimatedRouteCount := 0
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.ExcludedIPs)
	}
	routes := make([]winipcfg.RouteData, 0, estimatedRouteCount)
	addresses := make([]net.IPNet, len(conf.Interface.Addresses))
	var haveV4Address, haveV6Address bool
	for i, addr := range conf.Interface.Addresses {
		addresses[i] = addr.IPNet()
		if addr.Bits() == 32 {
			haveV4Address = true
		} else if addr.Bits() == 128 {
			haveV6Address = true
		}
	}

	for _, peer := range conf.Peers {
		for _, excluedip := range peer.ExcludedIPs {
			if (excluedip.Bits() == 32 && !haveV4Address) || (excluedip.Bits() == 128 && !haveV6Address) {
				continue
			}
			route := winipcfg.RouteData{
				Destination: excluedip.IPNet(),
				Metric:      0,
			}
			if excluedip.Bits() == 32 {
				route.NextHop = net.IPv4zero
			} else if excluedip.Bits() == 128 {
				route.NextHop = net.IPv6zero
			}
			routes = append(routes, route)
		}
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		return routes[i].Metric < routes[j].Metric ||
			bytes.Compare(routes[i].NextHop, routes[j].NextHop) == -1 ||
			bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP) == -1 ||
			bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask) == -1
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	err := SetDefaultRoutesForFamily(family, tun, deduplicatedRoutes)
	if err != nil {
		return nil
	}
	return nil
}

func enableFirewall(conf *conf.Config, tun *tun.NativeTun) error {
	restrictAll := false
	if len(conf.Peers) == 1 {
	nextallowedip:
		for _, allowedip := range conf.Peers[0].AllowedIPs {
			if allowedip.Cidr == 0 {
				for _, b := range allowedip.IP {
					if b != 0 {
						continue nextallowedip
					}
				}
				restrictAll = true
				break
			}
		}
	}
	if restrictAll && len(conf.Interface.DNS) == 0 {
		log.Println("Warning: no DNS server specified, despite having an allowed IPs of 0.0.0.0/0 or ::/0. There may be connectivity issues.")
	}
	return firewall.EnableFirewall(tun.LUID(), conf.Interface.DNS, restrictAll)
}
