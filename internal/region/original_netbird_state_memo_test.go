package region

import (
	"testing"
)

func TestOriginalNetBirdStateMemoScopes(t *testing.T) {
	id := new(byte)
	if originalNetBirdChecked(t.Context(), id) {
		t.Fatal("unscoped context remembered a check")
	}
	markOriginalNetBirdChecked(t.Context(), id)
	if originalNetBirdChecked(t.Context(), id) {
		t.Fatal("unscoped mark was retained")
	}
	scope := withOriginalNetBirdStateMemo(t.Context())
	if withOriginalNetBirdStateMemo(scope) != scope {
		t.Fatal("nested operation did not share its scope")
	}
	markOriginalNetBirdChecked(scope, id)
	if !originalNetBirdChecked(scope, id) || originalNetBirdChecked(scope, new(byte)) {
		t.Fatal("scope did not remember exactly its own check")
	}
	detached := withoutOriginalNetBirdStateMemo(scope)
	if originalNetBirdChecked(detached, id) {
		t.Fatal("detached writer reused a memoized check")
	}
	fresh := withOriginalNetBirdStateMemo(detached)
	if fresh == detached || originalNetBirdChecked(fresh, id) {
		t.Fatal("operation after a detached writer reused the earlier scope")
	}
}
