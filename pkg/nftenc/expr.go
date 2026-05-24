package nftenc

import expr "github.com/PRO-Robotech/nft-go/internal/expr-encoders"

type (
	// Export some internal types
	VerdictKind = expr.VerdictKind
)

const (
	// Export some internal constants
	VerdictReturn   = expr.VerdictReturn
	VerdictGoto     = expr.VerdictGoto
	VerdictJump     = expr.VerdictJump
	VerdictBreak    = expr.VerdictBreak
	VerdictContinue = expr.VerdictContinue
	VerdictDrop     = expr.VerdictDrop
	VerdictAccept   = expr.VerdictAccept
	VerdictStolen   = expr.VerdictStolen
	VerdictQueue    = expr.VerdictQueue
	VerdictRepeat   = expr.VerdictRepeat
	VerdictStop     = expr.VerdictStop
)
