// Code generated from internal/ops/registry.go by go generate; DO NOT EDIT.

package ops

// The denial codes (§5.6), one per CodeTable row.
var (
	InvalidArgs          = Code{"INVALID_ARGS"}
	UnknownOp            = Code{"UNKNOWN_OP"}
	TaskEnded            = Code{"TASK_ENDED"}
	NotFoundOrNotOwned   = Code{"NOT_FOUND_OR_NOT_OWNED"}
	DeniedPolicy         = Code{"DENIED_POLICY"}
	PolicyError          = Code{"POLICY_ERROR"}
	MemoryQuarantined    = Code{"MEMORY_QUARANTINED"}
	CapReached           = Code{"CAP_REACHED"}
	BusRefused           = Code{"BUS_REFUSED"}
	LeaseHeld            = Code{"LEASE_HELD"}
	NeedsSignature       = Code{"NEEDS_SIGNATURE"}
	AskDenied            = Code{"ASK_DENIED"}
	AskExpired           = Code{"ASK_EXPIRED"}
	AskCap               = Code{"ASK_CAP"}
	Stale                = Code{"STALE"}
	Busy                 = Code{"BUSY"}
	AdmissionRejected    = Code{"ADMISSION_REJECTED"}
	FloorNever           = Code{"FLOOR_NEVER"}
	HumanOnly            = Code{"HUMAN_ONLY"}
	RefOutsideNamespace  = Code{"REF_OUTSIDE_NAMESPACE"}
	OidNotInRemoteRepo   = Code{"OID_NOT_IN_REMOTE_REPO"}
	RemoteRejected       = Code{"REMOTE_REJECTED"}
	EffectFailed         = Code{"EFFECT_FAILED"}
	Indeterminate        = Code{"INDETERMINATE"}
	BatchAborted         = Code{"BATCH_ABORTED"}
	NestedSubvolume      = Code{"NESTED_SUBVOLUME"}
	AuditUnavailable     = Code{"AUDIT_UNAVAILABLE"}
	EgressNotAllowlisted = Code{"EGRESS_NOT_ALLOWLISTED"}
	EgressWrongRoute     = Code{"EGRESS_WRONG_ROUTE"}
	EgressNameRejected   = Code{"EGRESS_NAME_REJECTED"}
	EgressResolveFailed  = Code{"EGRESS_RESOLVE_FAILED"}
	EgressDialFailed     = Code{"EGRESS_DIAL_FAILED"}
	KeysRequestRejected  = Code{"KEYS_REQUEST_REJECTED"}
	KeysBudget           = Code{"KEYS_BUDGET"}
	KeysUpstream         = Code{"KEYS_UPSTREAM"}
	BrokerUnavailable    = Code{"BROKER_UNAVAILABLE"}
)

// genCodes is every generated code in table order; Validate checks it against CodeTable.
var genCodes = []Code{InvalidArgs, UnknownOp, TaskEnded, NotFoundOrNotOwned, DeniedPolicy, PolicyError, MemoryQuarantined, CapReached, BusRefused, LeaseHeld, NeedsSignature, AskDenied, AskExpired, AskCap, Stale, Busy, AdmissionRejected, FloorNever, HumanOnly, RefOutsideNamespace, OidNotInRemoteRepo, RemoteRejected, EffectFailed, Indeterminate, BatchAborted, NestedSubvolume, AuditUnavailable, EgressNotAllowlisted, EgressWrongRoute, EgressNameRejected, EgressResolveFailed, EgressDialFailed, KeysRequestRejected, KeysBudget, KeysUpstream, BrokerUnavailable}
