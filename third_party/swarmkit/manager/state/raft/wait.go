package raft

import (
	"fmt"
	"sync"
)

type waitItem struct {
	// channel to wait up the waiter
	ch chan interface{}
	// callback which is called synchronously when the wait is triggered
	cb       func()
	commitAt func(uint64)
	// callback which is called to cancel a waiter
	cancel func()
}

type wait struct {
	l sync.Mutex
	m map[uint64]waitItem
}

func newWait() *wait {
	return &wait{m: make(map[uint64]waitItem)}
}

func (w *wait) register(id uint64, cb func(), cancel func()) <-chan interface{} {
	return w.registerAt(id, cb, nil, cancel)
}

func (w *wait) registerAt(id uint64, cb func(), commitAt func(uint64), cancel func()) <-chan interface{} {
	w.l.Lock()
	defer w.l.Unlock()
	_, ok := w.m[id]
	if !ok {
		ch := make(chan interface{}, 1)
		w.m[id] = waitItem{ch: ch, cb: cb, commitAt: commitAt, cancel: cancel}
		return ch
	}
	panic(fmt.Sprintf("duplicate id %x", id))
}

func (w *wait) trigger(id uint64, x interface{}) bool {
	return w.triggerAt(id, x, 0)
}

func (w *wait) triggerAt(id uint64, x interface{}, index uint64) bool {
	w.l.Lock()
	waitItem, ok := w.m[id]
	delete(w.m, id)
	w.l.Unlock()
	if ok {
		if waitItem.cb != nil {
			waitItem.cb()
		}
		if waitItem.commitAt != nil {
			waitItem.commitAt(index)
		}
		waitItem.ch <- x
		return true
	}
	return false
}

func (w *wait) cancel(id uint64) {
	w.l.Lock()
	waitItem, ok := w.m[id]
	delete(w.m, id)
	w.l.Unlock()
	if ok {
		if waitItem.cancel != nil {
			waitItem.cancel()
		}
		close(waitItem.ch)
	}
}

func (w *wait) cancelAll() {
	w.l.Lock()
	defer w.l.Unlock()

	for id, waitItem := range w.m {
		delete(w.m, id)
		if waitItem.cancel != nil {
			waitItem.cancel()
		}
		close(waitItem.ch)
	}
}
