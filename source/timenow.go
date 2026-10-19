package main

import "time"

// TimeNow is what the clock in the gateway circle shows: this node's time, and how good chrony says it is.
type TimeNow struct {
	NowMS    int64   `json:"now_ms"`
	Running  bool    `json:"running"`
	Synced   bool    `json:"synced"`
	Stratum  int     `json:"stratum"`
	Ref      string  `json:"ref,omitempty"`
	OffsetMS float64 `json:"offset_ms"`
}

func nodeClock() TimeNow {
	c := chrony.State()
	return TimeNow{NowMS: time.Now().UnixMilli(), Running: c.Running, Synced: c.Synced, Stratum: c.Stratum, Ref: c.Ref, OffsetMS: c.OffsetMS}
}
