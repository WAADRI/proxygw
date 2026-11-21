package compress

import (
	"fmt"
	"io"
	"sync"
)

// Pool reuses zstd encoders and decoders across tunnel streams. Allocating a
// zstd encoder is comparatively expensive (window/history buffers), so streams
// should be wrapped through DefaultPool rather than with NewEncoder/NewDecoder
// directly. A Pool is safe for concurrent use; encoders and decoders taken from
// it must not be shared between streams.
type Pool struct {
	encoders sync.Pool
	decoders sync.Pool
}

// defaultPool backs DefaultPool. sync.Pool is designed as a package level
// cache, so the shared instance is intentional.
var defaultPool = &Pool{}

// DefaultPool returns the process wide pool used by WrapReadWrite.
func DefaultPool() *Pool { return defaultPool }

// GetEncoder returns an encoder attached to w. A pooled encoder is reset to the
// requested level; level changes recreate the underlying zstd writer.
func (p *Pool) GetEncoder(w io.Writer, level int) (*Encoder, error) {
	if w == nil {
		return nil, fmt.Errorf("compress: get encoder: %w", errNilStream)
	}
	if p == nil {
		p = DefaultPool()
	}
	if v := p.encoders.Get(); v != nil {
		e := v.(*Encoder)
		if err := e.reset(w, level); err != nil {
			return nil, err
		}
		return e, nil
	}
	e, err := NewEncoder(level)
	if err != nil {
		return nil, err
	}
	if err := e.reset(w, level); err != nil {
		return nil, err
	}
	return e, nil
}

// PutEncoder returns an encoder to the pool. The encoder should be Closed
// first; an encoder that is still open has its stream discarded (the caller
// loses unflushed writes by definition) and its background goroutine stopped.
func (p *Pool) PutEncoder(e *Encoder) {
	if e == nil {
		return
	}
	if p == nil {
		p = DefaultPool()
	}
	e.poolRelease()
	p.encoders.Put(e)
}

// GetDecoder returns a decoder attached to r.
func (p *Pool) GetDecoder(r io.Reader) (*Decoder, error) {
	if r == nil {
		return nil, fmt.Errorf("compress: get decoder: %w", errNilStream)
	}
	if p == nil {
		p = DefaultPool()
	}
	if v := p.decoders.Get(); v != nil {
		d := v.(*Decoder)
		if err := d.Reset(r); err != nil {
			return nil, err
		}
		return d, nil
	}
	d, err := NewDecoder()
	if err != nil {
		return nil, err
	}
	if err := d.Reset(r); err != nil {
		return nil, err
	}
	return d, nil
}

// PutDecoder returns a decoder to the pool. The decoder should be Closed first;
// one that is still open is detached from its reader. Poisoned decoders (which
// can no longer be reset) are dropped so a later reader cannot inherit a broken
// decoder.
func (p *Pool) PutDecoder(d *Decoder) {
	if d == nil {
		return
	}
	if p == nil {
		p = DefaultPool()
	}
	d.poolRelease()
	d.mu.Lock()
	poisoned := d.poisoned
	d.mu.Unlock()
	if poisoned {
		return
	}
	p.decoders.Put(d)
}
