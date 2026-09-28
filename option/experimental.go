package option

import (
	"github.com/sagernet/sing/common/byteformats"
	"github.com/sagernet/sing/common/json/badoption"
)

type ExperimentalOptions struct {
	CacheFile *CacheFileOptions `json:"cache_file,omitempty"`
	V2RayAPI  *V2RayAPIOptions  `json:"v2ray_api,omitempty"`
	Debug     *DebugOptions     `json:"debug,omitempty"`
}

type CacheFileOptions struct {
	Enabled       bool                     `json:"enabled,omitempty"`
	Path          string                   `json:"path,omitempty"`
	CacheID       string                   `json:"cache_id,omitempty"`
	StoreFakeIP   bool                     `json:"store_fakeip,omitempty"`
	StoreDNS      bool                     `json:"store_dns,omitempty"`
	BufferSize    *byteformats.MemoryBytes `json:"buffer_size,omitempty"`
	FlushInterval badoption.Duration       `json:"flush_interval,omitempty"`

	// Deprecated: replaced by store_dns
	StoreRDRC bool `json:"store_rdrc,omitempty" schema:"omit"`
	// Deprecated: replaced by store_dns
	RDRCTimeout badoption.Duration `json:"rdrc_timeout,omitempty" schema:"omit"`
}

type V2RayAPIOptions struct {
	Listen string                    `json:"listen,omitempty"`
	Stats  *V2RayStatsServiceOptions `json:"stats,omitempty"`
}

type V2RayStatsServiceOptions struct {
	Enabled   bool     `json:"enabled,omitempty"`
	Inbounds  []string `json:"inbounds,omitempty"`
	Outbounds []string `json:"outbounds,omitempty"`
	Users     []string `json:"users,omitempty"`
}
