// Package leader is single-instance election over a Postgres advisory lock.
//
// No etcd, no Consul, no ZooKeeper. The database is already a hard dependency
// and already provides exactly-one-holder semantics; adding a coordination
// service to run one loop would be a second thing to operate for no benefit.
//
// ⚠ WHAT THIS GIVES YOU IS A LEASE, NOT A FENCE.
//
// A holder can believe it still holds a lock it has lost. Its process stops for
// a GC pause, or its host is partitioned, or a middlebox resets its TCP
// connection; Postgres notices the session is gone, drops the lock, and another
// instance legitimately acquires it. Both now believe they lead, and no amount
// of re-checking closes the gap — the check and the work it guards cannot be
// made atomic across a network.
//
// So use this to keep N replicas from each doing the same polling. NEVER use it
// as the thing that makes an operation safe to perform once. That safety has to
// come from the operation itself: a unique constraint, a conditional update, an
// idempotency key. If removing this package would make a subsystem incorrect
// rather than merely wasteful, that subsystem has a bug.
package leader

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/axebom/axebom/libs/go-shared/platform/db"
)

// ID is an advisory-lock key.
//
// ⚠ POSTGRES ADVISORY LOCKS ARE ONE GLOBAL NAMESPACE FOR THE WHOLE DATABASE.
// There is no schema qualification and no per-service partition: key 1 taken by
// the scan service is the same key 1 the campaign service would take. Two
// subsystems that pick the same number silently serialise against each other,
// and the symptom is not an error — it is one of them simply never running,
// which nobody notices until an audit asks why.
//
// Hence a REGISTRY, in one file, rather than a constant in each package.
type ID int64

const (
	// ScanDeadlineReaper marks overdue engine runs as timed out.
	ScanDeadlineReaper ID = 1
	// CampaignScheduler dispatches due campaigns.
	CampaignScheduler ID = 2
	// NotificationRetry re-drives failed webhook deliveries.
	NotificationRetry ID = 3

	// Next subsystem takes 4. Add it here, not in your own package.
)

// String names the holder, for logs.
func (id ID) String() string {
	switch id {
	case ScanDeadlineReaper:
		return "scan-deadline-reaper"
	case CampaignScheduler:
		return "campaign-scheduler"
	case NotificationRetry:
		return "notification-retry"
	default:
		return fmt.Sprintf("unregistered-lock-%d", int64(id))
	}
}

// Lock is a held advisory lock.
//
// Safe for concurrent use, though the expected shape is one goroutine ticking.
type Lock struct {
	pool *db.Pool
	id   ID

	mu   sync.Mutex
	conn *pgxpool.Conn // non-nil exactly while this instance believes it leads
}

// NewLock builds a lock. It acquires nothing until Acquire is called.
func NewLock(pool *db.Pool, id ID) (*Lock, error) {
	if pool == nil {
		return nil, errors.New("leader: a lock needs a pool")
	}
	return &Lock{pool: pool, id: id}, nil
}

// Acquire reports whether this instance holds the lock.
//
// Calling it repeatedly is the intended usage — a scheduler calls it every
// tick. Two behaviours make that safe, and both are easy to get wrong:
//
// ⚠ IT DOES NOT RE-LOCK WHEN ALREADY HELD. pg_try_advisory_lock is REENTRANT
// within a session: calling it twice takes the lock twice and requires two
// unlocks. A tick loop that re-locked every thirty seconds would build a
// counter thousands deep, and the single pg_advisory_unlock on shutdown would
// leave the lock held — making a dead process the permanent leader until its
// connection is reaped.
//
// ⚠ IT VERIFIES THE HELD CONNECTION IS ALIVE. A held *pgxpool.Conn whose TCP
// session died still looks held from here. Without the check, an instance whose
// connection dropped would report leadership forever while Postgres had already
// handed the lock to somebody else.
func (l *Lock) Acquire(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.conn != nil {
		if err := l.conn.Ping(ctx); err == nil {
			return true, nil
		}
		// The session is gone, so the lock went with it. Drop the handle and
		// try to take it again below — competing fairly rather than assuming
		// the lock is still ours.
		l.conn.Release()
		l.conn = nil
	}

	// ⚠ A DEDICATED CONNECTION, NOT A POOLED QUERY. A session-scoped advisory
	// lock belongs to the session that took it. Running the lock through the
	// pool could take it on one connection and release it on another, which
	// silently does nothing — and would return the locked session to the pool
	// for unrelated work, so the lock's lifetime becomes whenever that
	// connection happens to be recycled.
	conn, err := l.pool.Raw().Acquire(ctx)
	if err != nil {
		return false, fmt.Errorf("leader: acquire connection: %w", err)
	}

	// pg_try_advisory_lock, NOT pg_advisory_lock. The blocking form queues
	// every replica behind the leader; when the leader dies they all wake at
	// once, and every one of them then holds a connection it is doing nothing
	// with.
	var acquired bool
	if err := conn.QueryRow(ctx,
		`SELECT pg_try_advisory_lock($1)`, int64(l.id)).Scan(&acquired); err != nil {
		conn.Release()
		return false, fmt.Errorf("leader: try advisory lock %s: %w", l.id, err)
	}
	if !acquired {
		// Another instance leads. Not an error — it is the expected state for
		// every replica but one, and logging it as a failure trains operators
		// to ignore the log.
		conn.Release()
		return false, nil
	}

	l.conn = conn
	return true, nil
}

// Release gives up leadership.
//
// Idempotent, and safe to call when the lock was never held. A rolling deploy
// calls it on shutdown so the next instance takes over in milliseconds instead
// of waiting for Postgres to notice a dead TCP session.
func (l *Lock) Release(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.conn == nil {
		return nil
	}
	conn := l.conn
	l.conn = nil

	// ⚠ THE CONNECTION IS RELEASED WHETHER OR NOT THE UNLOCK SUCCEEDS. If the
	// unlock statement fails the session is already unhealthy, and closing it
	// drops the lock anyway — which is the outcome we wanted. Holding the
	// connection back to retry would leak it.
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, int64(l.id)); err != nil {
		return fmt.Errorf("leader: release advisory lock %s: %w", l.id, err)
	}
	return nil
}

// Held reports whether this instance last saw itself as leader.
//
// ⚠ ADVISORY, AND NOT SAFE TO BRANCH ON FOR CORRECTNESS. It reports what this
// process believes, which is exactly the thing a partition invalidates. Use it
// for a metric or a log line, never as the guard before an action that must
// happen once.
func (l *Lock) Held() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conn != nil
}

// WithLeadership runs fn only if this instance can take the lock, releasing it
// afterwards.
//
// The shape for work that is occasional rather than continuous: a sweep every
// twenty seconds does not need to hold a connection in between.
func WithLeadership(ctx context.Context, pool *db.Pool, id ID, fn func(context.Context) error) error {
	lock, err := NewLock(pool, id)
	if err != nil {
		return err
	}
	held, err := lock.Acquire(ctx)
	if err != nil {
		return err
	}
	if !held {
		return nil
	}
	defer func() {
		// context.Background: ctx may already be cancelled, and releasing is
		// precisely the work that must still happen.
		_ = lock.Release(context.WithoutCancel(ctx))
	}()

	return fn(ctx)
}
