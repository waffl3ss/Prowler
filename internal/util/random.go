package util

import (
	"math/rand"
	"time"
)

func RandomDelay(minSeconds, maxSeconds int) {
	if maxSeconds <= minSeconds {
		maxSeconds = minSeconds + 1
	}
	delay := minSeconds + rand.Intn(maxSeconds-minSeconds)
	time.Sleep(time.Duration(delay) * time.Second)
}

func RandomDelayMillis(minMs, maxMs int) {
	if maxMs <= minMs {
		maxMs = minMs + 1
	}
	delay := minMs + rand.Intn(maxMs-minMs)
	time.Sleep(time.Duration(delay) * time.Millisecond)
}
