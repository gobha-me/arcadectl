package adminauth

import "time"

type timeT = time.Time

func timeNow() time.Time { return time.Now() }
