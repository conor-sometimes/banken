package response

import (
	"errors"
	"fmt"
	"time"

	"github.com/conor-sometimes/banken/internal/alert"
)

// OrderVersion is the work-order schema version. The drain checks it first and
// treats any other value as malformed (ErrMalformed), because an order it
// cannot be sure it understands must never reach a primitive. Bump it only
// when the on-disk shape changes incompatibly.
const OrderVersion = 1

// ErrMalformed marks a work order the drain cannot trust: bad JSON, an unknown
// version, or no target. It is a sentinel so the drain classifies a malformed
// order structurally (errors.Is), never by matching an error string. A
// malformed order is recorded and unlinked, never left to wedge the queue.
var ErrMalformed = errors.New("response: malformed work order")

// Order is the daemon's work order: the only way a decided action reaches a
// primitive after the two-process split. The daemon writes one to the spool;
// the drain re-decides from it in its own process and acts (or downgrades).
// See docs/design/response-architecture.md §2.3.
//
// The Alert is carried whole because Decide is pure over (alert, policy, ...)
// and the drain must be able to re-run it: a Decision alone is a conclusion
// the drain would have to trust. Decision is what the drain compares its own
// verdict against; it is never acted on directly. Policy is the hash the
// daemon decided under, for the record -- the drain always loads the policy
// from disk, and when the hashes differ the ledger shows which policy decided
// and which acted.
type Order struct {
	Version  int         `json:"version"`
	ID       string      `json:"id"`   // the decided ledger line's id; also the filename stem
	Time     time.Time   `json:"time"` // when the daemon decided
	Alert    alert.Alert `json:"alert"`
	Decision Decision    `json:"decision"`
	Policy   string      `json:"policy"`           // the policy hash the daemon decided under
	Banken   string      `json:"banken,omitempty"` // binary version
}

// validate reports whether the order is one the drain may process. A bad
// version or a nil target is ErrMalformed: the drain cannot safely re-decide
// or dispatch an order with no process or file to act on.
func (o Order) validate() error {
	if o.Version != OrderVersion {
		return fmt.Errorf("%w: unknown version %d (want %d)", ErrMalformed, o.Version, OrderVersion)
	}
	if o.Decision.Target.Process == nil && o.Decision.Target.File == nil {
		return fmt.Errorf("%w: order %s has no target", ErrMalformed, o.ID)
	}
	return nil
}
