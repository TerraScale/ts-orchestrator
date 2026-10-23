package swarmruntime

import (
	"errors"
	"strconv"
)

// ServiceGenerationAfter orders rollback after its failed rollout but before
// any later apply, even if rollback has the higher wall-clock generation.
func ServiceGenerationAfter(generation, rollbackOf, previousGeneration, previousRollbackOf int64) bool {
	next, previous := generation, previousGeneration
	if rollbackOf != 0 {
		next = rollbackOf
	}
	if previousRollbackOf != 0 {
		previous = previousRollbackOf
	}
	return next > previous || next == previous && generation > previousGeneration
}

func serviceGeneration(labels map[string]string) (generation, rollbackOf int64, err error) {
	for key, target := range map[string]*int64{LabelGeneration: &generation, LabelRollbackOf: &rollbackOf} {
		if value := labels[key]; value != "" {
			*target, err = strconv.ParseInt(value, 10, 64)
			if err != nil {
				return 0, 0, errors.New("invalid service generation or rollback ancestry")
			}
		}
	}
	if generation < 0 || rollbackOf < 0 || rollbackOf != 0 && rollbackOf >= generation {
		return 0, 0, errors.New("invalid service generation or rollback ancestry")
	}
	return generation, rollbackOf, nil
}
