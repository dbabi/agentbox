package rootd

import (
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"agentbox/internal/denial"
	"agentbox/internal/rootd/accounts"
	"agentbox/internal/rootd/quota"
)

// checkQuota is the qgroup monitor (#79), on rootd's timer and on the admin op quota.check. Inconsistent qgroups mean
// 2/0 limits nothing, so rootd fences its writers: every agent slice frozen, writing ops refused BUSY. Then it alerts,
// rescans, and thaws only once the rescan succeeded and the flag reads 0. It returns whether the fence is up; while a
// repair runs, a second call returns at once.
func (s *server) checkQuota() (bool, error) {
	if !s.fenceMu.TryLock() {
		return true, nil
	}
	defer s.fenceMu.Unlock()
	bad, err := s.inconsistent()
	if err != nil {
		log.Printf("quota: qgroups/inconsistent: %v", err)
		return s.fenced.Load(), err
	}
	if !bad {
		if s.fenced.Swap(false) { // at start too: a rootd that died mid-repair left its freeze behind
			s.freeze(false)
		}
		return false, nil
	}
	s.fenced.Store(true)
	if !s.alerted { // once per episode: a rescan that fails retries at each check without a new alert
		s.alerted = true
		msg := "qgroups are inconsistent, so the disk reserve limits nothing: agents are frozen and writing ops refused until a rescan repairs it"
		log.Printf("ALERT quota: %s", msg)
		go s.audit(map[string]any{"type": "ALERT", "reason": "qgroup_inconsistent"})
		if s.cfg.Alert != nil {
			go func() {
				if err := s.cfg.Alert("agentbox: disk quotas", msg); err != nil {
					log.Printf("alert not sent: %v", err)
					return
				}
				log.Printf("alert sent: %s", msg)
			}()
		}
	}
	s.freeze(true)
	for s.cfg.QuotaHold != "" {
		if _, err := os.Stat(s.cfg.QuotaHold); err != nil {
			break
		}
		time.Sleep(time.Second)
	}
	t0 := time.Now()
	if err := s.qrescan(); err != nil {
		log.Printf("quota: rescan: %v; writers stay frozen until the next check", err)
		return true, err
	}
	if bad, err = s.inconsistent(); err != nil || bad {
		log.Printf("quota: after the rescan the flag is still set (%v); writers stay frozen until the next check", err)
		return true, err
	}
	s.freeze(false)
	s.fenced.Store(false)
	s.alerted = false
	log.Printf("quota: rescan in %d ms; qgroups consistent, writers thawed", time.Since(t0).Milliseconds())
	return false, nil
}

// freeze sets cgroup.freeze on every active agent's user slice: its user manager, tasks and attach. An agent with no
// slice has nothing running. shortcut: agent slices are the only writers under 2/0 today; the git and proxy brokers
// join here once they write git/ and data/cache.
func (s *server) freeze(on bool) {
	all, err := accounts.List(s.db)
	if err != nil {
		log.Printf("quota: freeze %v: agents: %v", on, err)
		return
	}
	v := []byte("0")
	if on {
		v = []byte("1")
	}
	for _, a := range all {
		if !a.Active {
			continue
		}
		p := filepath.Join(s.cfg.Tasks.Cgroup, "user.slice", "user-"+strconv.Itoa(a.UID())+".slice", "cgroup.freeze")
		f, err := os.OpenFile(p, os.O_WRONLY, 0)
		if err == nil {
			_, err = f.Write(v)
			f.Close()
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("quota: freeze %v %s: %v", on, a.Name, err)
		}
	}
}

// fenceDeny is the writing ops' refusal while the fence is up: BUSY, which never names its reason to the agent (§5.6).
func (s *server) fenceDeny(op string) reply {
	if !s.fenced.Load() {
		return nil
	}
	return fenceReply(op)
}

func fenceReply(op string) reply {
	d := denial.New(denial.Busy, "floor", "floor.quota_fence", op, "", "")
	log.Printf("DENY by=floor op=%s code=%s rule=%s id=%s", d.Op, d.Code, d.Rule, d.ID)
	return reply{"ok": false, "reason": "quota_fence", "error": "qgroups are inconsistent: writing ops wait for the rescan", "denial": d}
}

// fenceAfter is the qgroup check after a subvolume change rootd made (#79, #205). It reads the flag at once and, when
// the flag is set or can't be read, raises the fence before it returns, so the caller's next step is refused. The
// repair runs in the background, after any check already running: that one may have read the flag before the change.
func (s *server) fenceAfter() {
	if bad, err := s.inconsistent(); err == nil && !bad {
		return
	} else if err != nil {
		log.Printf("quota: qgroups/inconsistent after a subvolume change: %v", err)
	}
	s.fenced.Store(true)
	go func() {
		s.fenceMu.Lock()
		s.fenceMu.Unlock()
		s.checkQuota()
	}()
}

// checkedBtrfs checks qgroups after each subvolume snapshot and delete rootd makes. A snapshot into 1/N marks qgroups
// inconsistent when 1/N shares extents outside itself (Linux's qgroup_snapshot_quick_inherit fails), and the flag is
// set when the snapshot returns, so the check runs at once (#205). For a delete the kernel drops the tree, and may mark
// qgroups inconsistent, only after the delete returns, so the check waits for `btrfs subvolume sync` first (#79).
type checkedBtrfs struct {
	Btrfs
	fence func()
}

func (c checkedBtrfs) Snapshot(src, dst, q string, ro bool) error {
	err := c.Btrfs.Snapshot(src, dst, q, ro)
	if err == nil {
		c.fence()
	}
	return err
}

func (c checkedBtrfs) Delete(p string) error {
	err := c.Btrfs.Delete(p)
	if err == nil {
		go func() {
			if _, err := quota.Run("btrfs", "subvolume", "sync", filepath.Dir(p)); err != nil {
				log.Printf("quota: subvolume sync after deleting %s: %v", p, err)
			}
			c.fence()
		}()
	}
	return err
}
