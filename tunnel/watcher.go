package tunnel

import (
	"bytes"
	"net"
	"sort"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/conf"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type Watcher struct {
	watcher *interfaceWatcher
}

func NewWatcher() *Watcher {
	w, err := watchInterface()
	if err != nil {
		return nil
	}
	return &Watcher{
		watcher: w,
	}
}

func (w *Watcher) Run(dev *device.Device, conf *conf.Config, tun *tun.NativeTun) {
	w.watcher.Configure(dev, conf, tun)
}

func (w *Watcher) Close() {
	if w.watcher != nil {
		w.watcher.Destroy()
		w.watcher = nil
	}
}

// 刷新网卡配置
func (w *Watcher) FlushConfig(conf *conf.Config, tun *tun.NativeTun) {
	luid := winipcfg.LUID(tun.LUID())
	// 刷新dns
	luid.SetDNSForFamily(windows.AF_INET, conf.Interface.DNS)
	luid.SetDNSForFamily(windows.AF_INET6, conf.Interface.DNS)
	// 刷新MTU
	ipif, err := luid.IPInterface(family)
	ipif.NLMTU = uint32(conf.Interface.MTU)
	tun.ForceMTU(int(ipif.NLMTU))
	_ = ipif.Set()
	// 清空route表
	luid.FlushRoutes(windows.AF_INET)
	luid.FlushRoutes(windows.AF_INET6)
	// 重新设置路由表
	estimatedRouteCount := 0
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.AllowedIPs)
	}

	routes := make([]winipcfg.RouteData, 0, estimatedRouteCount)
	var haveV4Address, haveV6Address bool
	for _, addr := range conf.Interface.Addresses {
		if addr.Bits() == 32 {
			haveV4Address = true
		} else if addr.Bits() == 128 {
			haveV6Address = true
		}
	}
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
				route.NextHop = net.IPv4zero
			} else if allowedip.Bits() == 128 {
				route.NextHop = net.IPv6zero
			}
			routes = append(routes, route)
		}
	}

	// 去除重复项
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
	// 添加路由
	for _, rd := range deduplicatedRoutes {
		luid.AddRoute(rd.Destination, rd.NextHop, rd.Metric)
	}
	// 添加excludeIp
	estimatedRouteCount = 0
	for _, peer := range conf.Peers {
		estimatedRouteCount += len(peer.ExcludedIPs)
	}
	routes = make([]winipcfg.RouteData, 0, estimatedRouteCount)
	addresses := make([]net.IPNet, len(conf.Interface.Addresses))
	//var haveV4Address, haveV6Address bool
	//判断地址是v6还是v4
	for i, addr := range conf.Interface.Addresses {
		addresses[i] = addr.IPNet()
		if addr.Bits() == 32 {
			haveV4Address = true
		} else if addr.Bits() == 128 {
			haveV6Address = true
		}
	}
	//取出排除ip项构造设置路由表的数据
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
	// 去除重复排除ip项
	deduplicatedRoutes = make([]*winipcfg.RouteData, 0, len(routes))
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
	//设置排除ip项，调用之前写的排除设置接口
	SetDefaultRoutesForFamily(windows.AF_INET, w.watcher.tun, deduplicatedRoutes)

}
