s#(https?://)[^/@[:space:]]+@#\1[REDACTED]@#g
s/("([Bb]earer|[Tt]oken|[Pp]assword|[Ss]ecret|[Aa]uth)"[[:space:]]*:[[:space:]]*")[^"]*/\1[REDACTED]/g
s/('([Bb]earer|[Tt]oken|[Pp]assword|[Ss]ecret|[Aa]uth)'[[:space:]]*:[[:space:]]*')[^']*/\1[REDACTED]/g
s/(["']?([Bb]earer|[Tt]oken|[Pp]assword|[Ss]ecret)["']?[[:space:]]*[:=][[:space:]]*["']?)[^"',[:space:]}]+/\1[REDACTED]/g
s/([Aa]uthorization["']?[[:space:]]*[:=][[:space:]]*["']?)([Bb]earer[[:space:]]+)?[^"',[:space:]}]+/\1[REDACTED]/g
