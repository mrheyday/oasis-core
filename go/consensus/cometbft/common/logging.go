package common

import (
	tmlog "github.com/cometbft/cometbft/libs/log"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

type logAdapter struct {
	*logging.Logger

	baseLogger    *logging.Logger
	suppressDebug bool

	keyVals []interface{}
}

func (a *logAdapter) With(keyvals ...interface{}) tmlog.Logger {
	// CometBFT uses `module` like oasis-node does, and to add insult to
	// injury will cave off child loggers with subsequence calls to
	// `With()`, resulting in multiple `module` keys.
	//
	// Do the right thing by:
	//  * Prefixing the `module` values with `cometbft:`
	//  * Coallece the multiple `module` values.
	//
	// This is more convoluted than it needs to be because the kit-log
	// prefix vector is private.

	findModule := func(vec []interface{}) (string, int) {
		for i, v := range vec {
			if i&1 != 0 {
				continue
			}

			k := v.(string)
			if k != "module" {
				continue
			}
			if i+1 > len(vec) {
				panic("With(): cometbft core logger, missing 'module' value")
			}

			vv := vec[i+1].(string)

			return vv, i + 1
		}
		return "", -1
	}

	parentMod, parentIdx := findModule(a.keyVals)

	childKeyVals := append([]interface{}{}, a.keyVals...)
	childMod, childIdx := findModule(keyvals)
	if childIdx < 0 {
		// "module" was not specified for this child, use the one belonging
		// to the parent.
		if parentIdx < 0 {
			// This should *NEVER* happen, if it does, it means that CometBFT
			// called `With()` on the base logAdapter without setting a module.
			panic("With(): cometbft core logger, no sensible parent 'module'")
		}
		childKeyVals = append(childKeyVals, keyvals...)
	} else if parentIdx < 0 {
		// No parent logger, this must be a child of the base logAdapter.
		keyvals[childIdx] = "cometbft:" + childMod
		childKeyVals = append(childKeyVals, keyvals...)
	} else {
		// Append the child's module to the parent's.
		childKeyVals[parentIdx] = parentMod + "/" + childMod
		for i, v := range keyvals {
			// And omit the non-re=written key/value from the those passed to
			// the kit-log logger.
			if i != childIdx-1 && i != childIdx {
				childKeyVals = append(childKeyVals, v)
			}
		}
	}

	return &logAdapter{
		Logger:        a.baseLogger.With(childKeyVals...),
		baseLogger:    a.baseLogger,
		suppressDebug: a.suppressDebug,
		keyVals:       childKeyVals,
	}
}

func (a *logAdapter) Info(msg string, keyvals ...interface{}) {
	a.Logger.Info(msg, keyvals...)
}

func (a *logAdapter) Error(msg string, keyvals ...interface{}) {
	a.Logger.Error(msg, keyvals...)
}

func (a *logAdapter) Debug(msg string, keyvals ...interface{}) {
	if !a.suppressDebug {
		a.Logger.Debug(msg, keyvals...)
	}
}

// NewLogAdapter creates a new adapter that adapts our logger to CometBFT APIs.
func NewLogAdapter(suppressDebug bool) tmlog.Logger {
	// Need an extra level of unwinding because the Debug wrapper
	// exists.
	//
	// This might be able to be replaced with the per-module log
	// level instead.
	return &logAdapter{
		Logger:        logging.GetLoggerEx("cometbft:base", 1),
		baseLogger:    logging.GetLoggerEx("", 1), // CometBFT sets the module, repeatedly.
		suppressDebug: suppressDebug,
	}
}
