package bootstrapmaterial

import (
	"time"
)

// nextSecond waits for the next whole second: brokers take only a cell
// claim issued strictly later than the one it replaces.
func nextSecond() { time.Sleep(time.Until(time.Unix(time.Now().Unix()+1, 0))) }
