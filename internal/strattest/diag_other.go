//go:build !windows

package strattest

// Diagnostics — проверки настроек ПК реализованы для Windows.
func Diagnostics() []string { return nil }
