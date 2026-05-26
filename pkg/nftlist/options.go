package nftlist

type (
	listOpts struct {
		noTextOut bool
		noJSONOut bool
	}
	listOpt interface {
		apply(*listOpts)
	}
	optFunc func(*listOpts)
)

var _ listOpt = optFunc(func(*listOpts) {})

func (f optFunc) apply(opts *listOpts) {
	f(opts)
}

// WithoutTextOutput -
func WithoutTextOutput() listOpt {
	return optFunc(func(opts *listOpts) {
		opts.noTextOut = true
	})
}

// WithoutJSONOutput -
func WithoutJSONOutput() listOpt {
	return optFunc(func(opts *listOpts) {
		opts.noJSONOut = true
	})
}
