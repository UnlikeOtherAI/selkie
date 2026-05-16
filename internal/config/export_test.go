package config

// ConfirmDevForTest returns a copy of c with devModeConfirmed forced to the
// given value. This file is only compiled under `go test` so production code
// cannot reach this function: the unexported devModeConfirmed field can only
// be set by Load() (env capture) or this helper. External tests in package
// config_test use this to construct Configs that pass Validate without
// going through the env.
func ConfirmDevForTest(c Config, confirmed bool) Config {
	c.devModeConfirmed = confirmed
	return c
}

// DevModeConfirmedForTest exposes the captured CONFIRM_DEV_MODE value to
// external tests so they can assert Load() captured what the env said.
func DevModeConfirmedForTest(c Config) bool {
	return c.devModeConfirmed
}
