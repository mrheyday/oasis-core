package migrations

const (
	// EmptyHandler is the name of the upgrade handler that doesn't perform any updates. This is
	// useful for upgrades that bump protocol versions but don't need any state migrations.
	EmptyHandler = "empty"
)

var _ Handler = (*emptyHandler)(nil)

type emptyHandler struct{}

func (th *emptyHandler) HasStartupUpgrade() bool {
	return false
}

func (th *emptyHandler) StartupUpgrade() error {
	// Nothing to do.
	return nil
}

func (th *emptyHandler) ConsensusUpgrade(interface{}) error {
	// Nothing to do.
	return nil
}

func init() {
	Register(EmptyHandler, &emptyHandler{})
}
