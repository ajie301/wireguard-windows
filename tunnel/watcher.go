package tunnel

import (
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/conf"
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
